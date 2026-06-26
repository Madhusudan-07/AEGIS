#!/usr/bin/env python3
"""Safely extend the append-only ratchet (the ONLY supported way to add coverage).

It (a) re-collects all current test ids and merges them into ``baseline_tests.txt``
(union — never removes), and (b) optionally locks a new regression test into
``corpus.lock.json`` with its content hash. Both writes are additive, so the ratchet
guard sees only additions.

Usage:
  # after adding tests anywhere, refresh the baseline (coverage grows):
  python security/ratchet/update_corpus.py --sync-baseline

  # lock a brand-new regression test for a confirmed finding (do this BEFORE the fix):
  python security/ratchet/update_corpus.py \
      --add tests/regression/test_REG_20260626_0002_xss.py \
      --id REG-20260626-0002 --threat "T1/A03" --summary "stored XSS in profile bio"
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "security/ratchet/baseline_tests.txt"
CORPUS_LOCK = ROOT / "security/ratchet/corpus.lock.json"


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


def sync_baseline() -> int:
    merged = sorted(load_baseline() | collect_test_ids())  # union: append-only
    header = (
        "# AEGIS ratchet baseline - every id here must always exist (Subsystem C).\n"
        "# Append-only: regenerate with `update_corpus.py --sync-baseline`. Never hand-delete.\n"
    )
    BASELINE.write_text(header + "\n".join(merged) + "\n", encoding="utf-8")
    print(f"baseline synced: {len(merged)} test ids")
    return len(merged)


def load_lock() -> dict:
    if CORPUS_LOCK.exists():
        return json.loads(CORPUS_LOCK.read_text())
    return {"version": 1, "entries": []}


def add_entry(path: str, id_: str, threat: str, summary: str) -> None:
    target = ROOT / path
    if not target.exists():
        sys.exit(f"error: regression test not found: {path}")
    lock = load_lock()
    if any(e["id"] == id_ for e in lock["entries"]):
        sys.exit(f"error: corpus id already locked (corpus is append-only): {id_}")
    if any(e["path"] == path for e in lock["entries"]):
        sys.exit(f"error: path already locked: {path}")
    lock["entries"].append({
        "id": id_,
        "path": path,
        "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        "threat": threat,
        "summary": summary,
        "added": date.today().isoformat(),
    })
    lock["entries"].sort(key=lambda e: e["id"])
    CORPUS_LOCK.write_text(json.dumps(lock, indent=2) + "\n")
    print(f"locked {id_} -> {path}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sync-baseline", action="store_true", help="merge current tests into baseline")
    ap.add_argument("--add", metavar="PATH", help="path to a new regression test to lock")
    ap.add_argument("--id", help="regression id, e.g. REG-20260626-0002")
    ap.add_argument("--threat", default="", help="STRIDE/OWASP mapping, e.g. 'S1/A07'")
    ap.add_argument("--summary", default="", help="one-line description")
    args = ap.parse_args()

    if args.add:
        if not args.id:
            sys.exit("error: --add requires --id")
        add_entry(args.add, args.id, args.threat, args.summary)
    # Always (re)sync the baseline so the newly added test is guaranteed forever.
    sync_baseline()


if __name__ == "__main__":
    main()
