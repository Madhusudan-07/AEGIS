"""Audit: tamper-evident hash chain + redaction (ASVS V7 / OWASP A09)."""
from __future__ import annotations

from aegis.core.modules.audit import AuditLog
from tests.helpers import make_ctx


def test_chain_verifies_when_intact():
    log = AuditLog()
    for i in range(5):
        log.record("event", n=i)
    assert log.verify_chain() is True


def test_tampering_breaks_the_chain():
    log = AuditLog()
    for i in range(5):
        log.record("event", n=i)
    log.entries[2]["fields"]["n"] = 999  # forge a past record
    assert log.verify_chain() is False


def test_deletion_breaks_the_chain():
    log = AuditLog()
    for i in range(5):
        log.record("event", n=i)
    del log._chain[2]
    assert log.verify_chain() is False


def test_secrets_are_redacted_in_audit():
    log = AuditLog()
    entry = log.record("login", password="hunter2", api_key="sk-abcdef123456", note="ok")
    assert entry["fields"]["password"] == "***REDACTED***"
    assert entry["fields"]["api_key"] == "***REDACTED***"
    assert entry["fields"]["note"] == "ok"


def test_jwt_and_email_redacted_from_freetext():
    log = AuditLog()
    jwt_like = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij"
    entry = log.record("note", text=f"user a@b.com token {jwt_like} signed in")
    assert "a@b.com" not in entry["fields"]["text"]
    assert jwt_like not in entry["fields"]["text"]


def test_engine_audits_denies(engine):
    engine.handle_request(make_ctx(method="POST", path="/orders"))  # CSRF deny
    events = [e["event"] for e in engine.audit.entries]
    assert "aegis.deny" in events
    assert engine.audit.verify_chain() is True
