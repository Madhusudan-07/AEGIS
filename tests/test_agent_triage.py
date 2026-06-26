"""Unit tests for the Subsystem B triage agent's deterministic core.

Proves the agent dedupes, drops false positives with reasons, and writes a MEANINGFUL
regression test for dependency findings (never a fake test for classes it can't assert).
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("aegis_run_agent", ROOT / "security/agent/run_agent.py")
agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent)


def test_normalize_pip_audit():
    data = {"dependencies": [
        {"name": "examplelib", "version": "1.0.0", "vulns": [{"id": "CVE-2099-0001", "fix_versions": ["1.0.1"]}]},
        {"name": "safe", "version": "2.0.0", "vulns": []},
    ]}
    out = agent.normalize_pip_audit(data)
    assert len(out) == 1
    assert out[0]["kind"] == "dependency" and out[0]["rule"] == "CVE-2099-0001"
    assert out[0]["fix"] == "1.0.1"


def test_triage_dedupes_and_drops_false_positives():
    findings = [
        {"source": "bandit", "kind": "sast", "rule": "B105", "location": "aegis/core/engine.py:193", "summary": "x"},
        {"source": "bandit", "kind": "sast", "rule": "B105", "location": "aegis/core/engine.py:193", "summary": "x"},  # dup
        {"source": "bandit", "kind": "sast", "rule": "B110", "location": "aegis/core/engine.py:160", "summary": "y"},
    ]
    fps = {"bandit:B105:aegis/core/engine.py"}
    confirmed, discarded = agent.triage(findings, fps)
    rules = sorted(f["rule"] for f in confirmed)
    assert rules == ["B110"]                 # B105 dropped as FP, dup removed
    assert len(discarded) == 1 and "false positive" in discarded[0]["discard_reason"]


def test_fingerprint_ignores_line_drift():
    a = {"source": "bandit", "rule": "B110", "location": "aegis/x.py:10"}
    b = {"source": "bandit", "rule": "B110", "location": "aegis/x.py:42"}
    assert agent.fingerprint(a) == agent.fingerprint(b)


def test_dependency_regression_is_a_real_assertion(tmp_path):
    f = {"kind": "dependency", "name": "examplelib", "version": "1.0.0",
         "rule": "CVE-2099-0001", "fix": "1.0.1", "summary": "examplelib 1.0.0 affected"}
    path = agent.write_regression(f, "REG-20990101-AGENT01", tmp_path)
    assert path is not None
    src = path.read_text()
    assert "_installed_version" in src and 'examplelib' in src
    assert "assert" in src


def test_non_dependency_finding_is_flagged_not_faked(tmp_path):
    f = {"kind": "sast", "name": None, "rule": "B110", "location": "x.py:1", "summary": "z"}
    # The agent refuses to auto-write a test it cannot make meaningful.
    assert agent.write_regression(f, "REG-x", tmp_path) is None


def test_pr_body_states_propose_only():
    body = agent.pr_body([], [], [], [])
    assert "propose-only" in body.lower()
    assert "human" in body.lower()
