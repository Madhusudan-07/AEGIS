"""Deception / honeypot module — traps scanners and cuts them off (advances G3)."""
from __future__ import annotations

from tests.helpers import make_ctx


def test_honeypot_hit_is_trapped_and_blocks_the_ip(engine, alerts):
    ip = "203.0.113.99"

    # 1. Touching a decoy path is denied (as a bland 404 — no tell).
    deny = engine.handle_request(make_ctx(path="/.env", remote_addr=ip))
    assert deny is not None and deny.status == 404

    # 2. That IP is now cut off from a perfectly normal endpoint, too.
    deny2 = engine.handle_request(make_ctx(path="/", remote_addr=ip))
    assert deny2 is not None and deny2.status == 404

    # 3. The trap was audited and alerted.
    assert any(e["event"] == "deception.honeypot_hit" for e in engine.audit.entries)
    assert any(kind == "deception.attacker_trapped" for kind, _ in alerts)


def test_other_clients_are_unaffected(engine):
    engine.handle_request(make_ctx(path="/.git/config", remote_addr="203.0.113.50"))  # trap one IP
    # A different, innocent client sails through.
    assert engine.handle_request(make_ctx(path="/", remote_addr="198.51.100.7")) is None


def test_normal_paths_are_not_trapped(engine):
    assert engine.handle_request(make_ctx(path="/", remote_addr="198.51.100.1")) is None
    assert engine.handle_request(make_ctx(path="/api/notes", remote_addr="198.51.100.1")) is None


def test_honeypot_matches_subpaths(engine):
    deny = engine.handle_request(make_ctx(path="/.git/config", remote_addr="203.0.113.77"))
    assert deny is not None and deny.status == 404
