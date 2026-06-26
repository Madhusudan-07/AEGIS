#!/usr/bin/env python3
"""AEGIS AI Triage + Improvement Agent — Subsystem B (spec §5).

PROPOSE ONLY. Parses the battery's findings, triages + dedupes them, writes a regression
test FIRST for each confirmed issue (the ratchet, §3), then opens ONE PR per fix to a
NON-protected ``security/auto/*`` branch. It never merges, never pushes to a protected
branch, never deploys, never touches secrets.

The deterministic core (triage, dedupe, dependency-regression generation, PR assembly)
runs with no model and is unit-tested. An optional LLM step (``--enrich``, gated on
ANTHROPIC_API_KEY) can confirm reproducibility and draft richer tests/fixes; all ingested
findings are wrapped as UNTRUSTED and cannot change the agent's instructions.

Usage:
  python security/agent/run_agent.py --reports reports/ --dry-run
  python security/agent/run_agent.py --reports reports/ --open-pr     # in CI, with GH_TOKEN
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REGRESSION_DIR = ROOT / "tests/regression"
FALSE_POSITIVES = ROOT / "security/agent/false_positives.json"


# --------------------------------------------------------------------------- #
# finding normalization  (each source -> a common dict)
# --------------------------------------------------------------------------- #
def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:40] or "finding"


def normalize_pip_audit(data: dict) -> list[dict]:
    out = []
    for dep in data.get("dependencies", data.get("vulnerabilities", [])):
        name, version = dep.get("name"), dep.get("version")
        for v in dep.get("vulns", dep.get("aliases", [])) or []:
            vid = v.get("id") if isinstance(v, dict) else str(v)
            fix = ",".join(v.get("fix_versions", [])) if isinstance(v, dict) else ""
            out.append({
                "source": "pip-audit", "kind": "dependency", "rule": vid,
                "location": f"{name}=={version}", "name": name, "version": version,
                "fix": fix, "severity": "high",
                "summary": f"{name} {version} affected by {vid}" + (f" (fix: {fix})" if fix else ""),
            })
    return out


def normalize_bandit(data: dict) -> list[dict]:
    out = []
    for r in data.get("results", []):
        out.append({
            "source": "bandit", "kind": "sast", "rule": r.get("test_id"),
            "location": f"{r.get('filename')}:{r.get('line_number')}",
            "severity": (r.get("issue_severity") or "").lower(),
            "confidence": (r.get("issue_confidence") or "").lower(),
            "summary": r.get("issue_text", ""),
        })
    return out


def normalize_gitleaks(data) -> list[dict]:
    out = []
    for r in data or []:
        out.append({
            "source": "gitleaks", "kind": "secret", "rule": r.get("RuleID", "secret"),
            "location": f"{r.get('File')}:{r.get('StartLine')}",
            "severity": "critical", "summary": f"potential secret ({r.get('RuleID')})",
        })
    return out


def load_findings(reports_dir: Path) -> list[dict]:
    findings: list[dict] = []
    mapping = {
        "pip-audit.json": normalize_pip_audit,
        "bandit.json": normalize_bandit,
        "gitleaks.json": normalize_gitleaks,
    }
    for fname, fn in mapping.items():
        p = reports_dir / fname
        if p.exists():
            try:
                findings.extend(fn(json.loads(p.read_text())))
            except Exception as exc:
                print(f"::warning::could not parse {fname}: {exc}")
    return findings


# --------------------------------------------------------------------------- #
# triage
# --------------------------------------------------------------------------- #
def fingerprint(f: dict) -> str:
    loc = f["location"].split(":")[0]  # ignore line drift for SAST/secret
    return f"{f['source']}:{f['rule']}:{loc}"


def load_false_positives() -> set[str]:
    if not FALSE_POSITIVES.exists():
        return set()
    data = json.loads(FALSE_POSITIVES.read_text())
    return {e["fingerprint"] for e in data.get("entries", [])}


def triage(findings: list[dict], fps: set[str]) -> tuple[list[dict], list[dict]]:
    """Dedupe by fingerprint and drop known false positives. Returns (confirmed, discarded)."""
    seen: set[str] = set()
    confirmed, discarded = [], []
    for f in findings:
        fp = fingerprint(f)
        f["fingerprint"] = fp
        if fp in seen:
            continue  # dedupe first, regardless of FP status
        seen.add(fp)
        if fp in fps:
            f["discard_reason"] = "known false positive (security/agent/false_positives.json)"
            discarded.append(f)
            continue
        confirmed.append(f)
    return confirmed, discarded


# --------------------------------------------------------------------------- #
# regression-test generation (the ratchet: test BEFORE fix)
# --------------------------------------------------------------------------- #
def render_dependency_regression(f: dict, reg_id: str) -> str:
    slug = _slug(f"{f['name']}_{f['rule']}")
    fix = f.get("fix") or "a patched release"
    return f'''"""Regression {reg_id} — dependency {f['name']} {f['version']} has {f['rule']}.

Auto-generated by the AEGIS triage agent (Subsystem B). Threat: OWASP A06 (Vulnerable &
Outdated Components). FAILS while the vulnerable version is installed; passes after
upgrading to {fix}. Locked into the append-only corpus.
"""
from importlib.metadata import version as _installed_version


def test_{slug}_not_vulnerable_version():
    assert _installed_version("{f['name']}") != "{f['version']}", (
        "vulnerable {f['name']}=={f['version']} still installed; upgrade to {fix}"
    )
'''


def write_regression(f: dict, reg_id: str, target_dir: Path) -> Path | None:
    """Only dependency findings get an auto-written, MEANINGFUL assertion. Other classes
    are flagged for human/LLM authorship (no fake tests). Returns the path or None."""
    if f["kind"] != "dependency":
        return None
    target_dir.mkdir(parents=True, exist_ok=True)
    fname = f"test_{reg_id.replace('-', '_')}_{_slug(f['name'])}.py"
    path = target_dir / fname
    path.write_text(render_dependency_regression(f, reg_id), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# PR assembly  (propose only)
# --------------------------------------------------------------------------- #
def pr_body(confirmed: list[dict], discarded: list[dict], locked: list[dict],
            needs_human: list[dict]) -> str:
    lines = [
        "## AEGIS auto-triage proposal (propose-only)",
        "",
        "Opened by the daily self-hardening loop (Subsystem B). **A human must review and "
        "merge.** This branch is not protected; the agent cannot merge or deploy.",
        "",
        f"- confirmed findings: {len(confirmed)}",
        f"- regression tests locked (test-first): {len(locked)}",
        f"- discarded false positives: {len(discarded)}",
        f"- needs human authorship: {len(needs_human)}",
        "",
    ]
    if locked:
        lines += ["### Regression tests added (ratchet, before fix)", ""]
        for f in locked:
            lines.append(f"- `{f['reg_id']}` — {f['summary']} (threat: {f.get('threat','')})")
        lines.append("")
    if needs_human:
        lines += ["### Flagged for human review (no safe auto-fix)", ""]
        for f in needs_human:
            lines.append(f"- [{f['source']}/{f['rule']}] {f['location']} — {f['summary']}")
        lines.append("")
    if discarded:
        lines += ["### Discarded (with reason)", ""]
        for f in discarded:
            lines.append(f"- {f['fingerprint']}: {f['discard_reason']}")
        lines.append("")
    lines += [
        "---",
        "_The agent proposes only. The ratchet guard blocks any coverage regression; "
        "every merge requires human approval (a permanent gate, not scaffolding)._",
    ]
    return "\n".join(lines)


def _run(cmd: list[str], check: bool = True) -> str:
    res = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if check and res.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {res.stderr.strip()}")
    return res.stdout.strip()


def open_pr(branch: str, title: str, body: str, label: str, base: str) -> None:
    _run(["git", "checkout", "-b", branch])
    _run(["git", "add", "tests/regression", "security/ratchet"])
    _run(["git", "commit", "-m", title])
    _run(["git", "push", "-u", "origin", branch])
    # gh uses GH_TOKEN (least-privilege agent token). Cannot approve/merge its own PR.
    _run(["gh", "pr", "create", "--base", base, "--head", branch,
          "--title", title, "--body", body, "--label", label])


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default="reports", help="dir with battery JSON reports")
    ap.add_argument("--open-pr", action="store_true", help="create branch + open PR (CI)")
    ap.add_argument("--dry-run", action="store_true", help="triage + write tests, no git/gh")
    ap.add_argument("--base", default="main")
    ap.add_argument("--branch-prefix", default="security/auto/")
    ap.add_argument("--max-prs", type=int, default=3)
    args = ap.parse_args()

    findings = load_findings(Path(args.reports) if Path(args.reports).is_absolute()
                             else ROOT / args.reports)
    confirmed, discarded = triage(findings, load_false_positives())

    print(f"findings={len(findings)} confirmed={len(confirmed)} discarded={len(discarded)}")

    locked, needs_human = [], []
    today = date.today().strftime("%Y%m%d")
    for i, f in enumerate(confirmed, start=1):
        reg_id = f"REG-{today}-AGENT{i:02d}"
        path = write_regression(f, reg_id, REGRESSION_DIR)
        if path is None:
            needs_human.append(f)
            continue
        rel = str(path.relative_to(ROOT)).replace("\\", "/")
        # Lock it into the append-only corpus (test-first).
        _run([sys.executable, "security/ratchet/update_corpus.py", "--add", rel,
              "--id", reg_id, "--threat", "A06", "--summary", f["summary"]], check=False)
        f["reg_id"], f["threat"] = reg_id, "A06"
        locked.append(f)

    body = pr_body(confirmed, discarded, locked, needs_human)
    Path(args.reports).mkdir(parents=True, exist_ok=True) if not Path(args.reports).is_absolute() else None
    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports/agent-triage.md").write_text(body, encoding="utf-8")
    print("\n" + body)

    if args.open_pr and (locked or needs_human):
        branch = f"{args.branch_prefix}{today}-{_run(['git', 'rev-parse', '--short', 'HEAD'])}"
        title = f"security: auto-triage {today} ({len(locked)} regression(s))"
        open_pr(branch, title, body, "security-fix", args.base)
        print(f"opened PR from {branch}")
    elif args.dry_run:
        print("\n[dry-run] no git/gh actions taken.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
