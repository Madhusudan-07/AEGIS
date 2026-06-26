#!/usr/bin/env python3
"""AEGIS Ratchet Guard — Subsystem C (spec §6). A REQUIRED, security-critical CI check.

The ratchet makes AEGIS monotonic: coverage can only grow, and no past finding can
regress. This guard FAILS a pull request that:

  1. removes or renames an existing baseline test  (coverage would shrink), OR
  2. deletes or alters a locked regression test     (a past finding could come back), OR
  3. shrinks the baseline / corpus lockfiles         (the ratchet itself being filed down), OR
  4. adds a security fix (label ``security-fix``) without adding a regression test first.

It additionally FLAGS changes to protected gate files (workflows, this guard, CODEOWNERS,
pyproject gate config) for mandatory senior review.

A human may override (1)-(4) by applying the ``security-override-approved`` label, which
the workflow surfaces as ``RATCHET_OVERRIDE=1`` and which is LOGGED here. The guard never
overrides itself — changes to this file require senior review via CODEOWNERS (§7).

Exit code 0 = pass (or overridden), 1 = blocked.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "security/ratchet/baseline_tests.txt"
CORPUS_LOCK = ROOT / "security/ratchet/corpus.lock.json"
REGRESSION_DIR = ROOT / "tests/regression"

# Touching any of these changes the loop's own guarantees -> senior review required.
PROTECTED_GATE_FILES = [
    ".github/workflows/daily-security.yml",
    ".github/workflows/pr-security.yml",
    ".github/workflows/security-agent.yml",
    "security/ratchet/ratchet_guard.py",
    "security/ratchet/update_corpus.py",
    ".github/CODEOWNERS",
    "pyproject.toml",
]

# Paths that count as "a control / defensive code" for the fix-needs-test rule.
CONTROL_PATHS = ("aegis/core/", "aegis/adapters/")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _run(cmd: list[str]) -> str:
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True).stdout


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def collect_test_ids() -> set[str]:
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=ROOT, capture_output=True, text=True,
    ).stdout
    return {line.strip() for line in out.splitlines() if "::" in line}


def load_baseline() -> set[str]:
    if not BASELINE.exists():
        return set()
    return {l.strip() for l in BASELINE.read_text().splitlines() if l.strip() and not l.startswith("#")}


def load_corpus() -> list[dict]:
    if not CORPUS_LOCK.exists():
        return []
    return json.loads(CORPUS_LOCK.read_text()).get("entries", [])


def changed_files(base_ref: str | None) -> list[str]:
    if not base_ref:
        return []
    out = _run(["git", "diff", "--name-only", f"{base_ref}...HEAD"])
    return [l.strip() for l in out.splitlines() if l.strip()]


def removed_lines(base_ref: str | None, path: str) -> list[str]:
    """Lines deleted from ``path`` in this PR (additive-only enforcement)."""
    if not base_ref:
        return []
    out = _run(["git", "diff", "--unified=0", f"{base_ref}...HEAD", "--", path])
    return [l for l in out.splitlines() if l.startswith("-") and not l.startswith("---")]


def gh_annotate(level: str, msg: str) -> None:
    print(f"::{level}::{msg}")


# --------------------------------------------------------------------------- #
# checks
# --------------------------------------------------------------------------- #
def main() -> int:
    override = os.environ.get("RATCHET_OVERRIDE", "").strip().lower() in ("1", "true", "yes")
    base_ref = os.environ.get("RATCHET_BASE") or None
    pr_labels = {l.strip() for l in os.environ.get("PR_LABELS", "").split(",") if l.strip()}
    have_git_base = bool(base_ref)

    blocking: list[str] = []
    warnings: list[str] = []

    # (1) No baseline test may disappear.
    baseline = load_baseline()
    current = collect_test_ids()
    if baseline:
        removed_tests = sorted(baseline - current)
        if removed_tests:
            blocking.append(
                "Baseline tests removed/renamed (coverage would shrink): "
                + ", ".join(removed_tests[:10]) + (" ..." if len(removed_tests) > 10 else "")
            )
    else:
        warnings.append("No baseline_tests.txt found — run update_corpus.py to seed it.")

    # (2) Locked regression tests are immutable.
    for entry in load_corpus():
        p = ROOT / entry["path"]
        if not p.exists():
            blocking.append(f"Locked regression test deleted: {entry['path']} ({entry['id']})")
        elif sha256_file(p) != entry["sha256"]:
            blocking.append(f"Locked regression test ALTERED: {entry['path']} ({entry['id']})")

    # (3) The lockfiles themselves must only grow (no filing down the ratchet).
    if have_git_base:
        for f in ("security/ratchet/baseline_tests.txt", "security/ratchet/corpus.lock.json"):
            dels = removed_lines(base_ref, f)
            # corpus.lock.json reformat could show '-' lines; flag any non-trivial deletion.
            meaningful = [d for d in dels if d.strip(" -\t{}[],") not in ("",)]
            if meaningful:
                blocking.append(f"Ratchet file had content removed: {f} ({len(meaningful)} line(s))")

    # (4) A security-fix PR must add a regression test in the same PR.
    if have_git_base and ("security-fix" in pr_labels):
        files = changed_files(base_ref)
        touched_control = any(any(f.startswith(c) for c in CONTROL_PATHS) for f in files)
        added_regression = any(f.startswith("tests/regression/") for f in files)
        if touched_control and not added_regression:
            blocking.append(
                "security-fix PR changes a control under aegis/ but adds no "
                "tests/regression/ test — fixes must ship their regression first (§3)."
            )

    # (FLAG) Protected gate-file changes -> senior review (CODEOWNERS enforces the gate).
    if have_git_base:
        files = set(changed_files(base_ref))
        touched_gate = sorted(files & set(PROTECTED_GATE_FILES))
        if touched_gate:
            warnings.append(
                "Protected gate files changed — senior review REQUIRED (CODEOWNERS): "
                + ", ".join(touched_gate)
            )
        if "security/ratchet/ratchet_guard.py" in files:
            warnings.append(
                "The ratchet guard itself is being modified. This is security-critical; "
                "it must not be merged without senior human review."
            )

    # --------------------------------------------------------------------- #
    # verdict
    # --------------------------------------------------------------------- #
    for w in warnings:
        gh_annotate("warning", w)

    if not blocking:
        print("[PASS] Ratchet guard: coverage is monotonic, corpus intact.")
        return 0

    if override:
        print("::warning::RATCHET OVERRIDE ACTIVE (security-override-approved). "
              "The following would have BLOCKED this PR and are now logged for audit:")
        for b in blocking:
            gh_annotate("warning", "OVERRIDDEN: " + b)
        print("Override is human-approved and logged. Proceeding.")
        return 0

    print("\n[BLOCKED] Ratchet guard: the loop may only ADD constraints, never remove them.\n")
    for b in blocking:
        gh_annotate("error", b)
    print("\nTo override (human, logged): apply the 'security-override-approved' label and "
          "re-run. To add a fix correctly: add its regression test under tests/regression/ "
          "via security/ratchet/update_corpus.py FIRST.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
