"""Durable audit sinks — the hash-chained trail survives beyond process memory.

FileAuditSink is exercised for real (append-only JSONL, restart continuity, chain fidelity).
PostgresAuditSink is exercised against an injected fake connection — asserting append-only
DDL + parameterized INSERT — so no live Postgres is needed in CI. fan_out is proven to feed
every sink and to surface a failing one (so AuditLog can log the gap).
"""
from __future__ import annotations

import json

import pytest

from aegis.core.modules.audit import AuditLog
from aegis.core.sinks import FileAuditSink, PostgresAuditSink, fan_out


# --- FileAuditSink -----------------------------------------------------------
def test_file_sink_persists_and_survives_restart(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(sink=FileAuditSink(path))
    log.record("login.ok", user="alice")
    log.record("authz.deny", perm="users:read")

    persisted = FileAuditSink(path).read_all()   # fresh handle == "after a restart"
    assert [e["seq"] for e in persisted] == [0, 1]
    assert [e["event"] for e in persisted] == ["login.ok", "authz.deny"]

    # A new sink on the same path appends rather than truncating (durable history).
    FileAuditSink(path)({"seq": 2, "ts": 1.0, "event": "manual",
                         "fields": {}, "prev_hash": "0" * 64, "hash": "z" * 64})
    assert len(FileAuditSink(path).read_all()) == 3


def test_file_sink_preserves_the_hash_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    sink = FileAuditSink(path)
    log = AuditLog(sink=sink)
    log.record("a")
    log.record("b")
    stored = sink.read_all()
    # Stored hashes match the in-memory chain, and links are intact on disk.
    assert stored[0]["hash"] == log.entries[0]["hash"]
    assert stored[1]["prev_hash"] == stored[0]["hash"]


def test_file_sink_redaction_is_already_applied(tmp_path):
    path = tmp_path / "audit.jsonl"
    sink = FileAuditSink(path)
    AuditLog(sink=sink).record("login", password="hunter2", token="secret-abc")
    blob = path.read_text(encoding="utf-8")
    assert "hunter2" not in blob and "secret-abc" not in blob   # redacted upstream


# --- fan_out -----------------------------------------------------------------
def test_fan_out_feeds_every_sink_and_ignores_none():
    a, b = [], []
    sink = fan_out(a.append, None, b.append)
    sink({"event": "x"})
    assert a == [{"event": "x"}] and b == [{"event": "x"}]


def test_fan_out_attempts_all_then_raises_first_failure():
    got = []

    def boom(_entry):
        raise RuntimeError("disk full")

    sink = fan_out(boom, got.append)          # bad sink first
    with pytest.raises(RuntimeError, match="disk full"):
        sink({"event": "x"})
    assert got == [{"event": "x"}]            # the healthy sink still ran


def test_fan_out_failure_is_audited_as_sink_failure():
    def boom(_entry):
        raise RuntimeError("nope")

    delivered = []
    log = AuditLog(sink=fan_out(boom, delivered.append))
    log.record("deny", ip="1.2.3.4")
    # The live sink received the event; the broken durable sink produced a recorded gap.
    assert delivered and delivered[0]["event"] == "deny"
    assert any(e["event"] == "audit.sink_failure" for e in log.entries)


# --- PostgresAuditSink (injected fake connection) ----------------------------
class _FakeCursor:
    def __init__(self, calls):
        self._calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self._calls.append((sql, params))


class _FakeConn:
    def __init__(self):
        self.calls = []
        self.commits = 0

    def cursor(self):
        return _FakeCursor(self.calls)

    def commit(self):
        self.commits += 1


def test_postgres_sink_creates_table_on_init():
    conn = _FakeConn()
    PostgresAuditSink(connection=conn, table="aegis_audit")
    assert any("CREATE TABLE IF NOT EXISTS aegis_audit" in sql for sql, _ in conn.calls)


def test_postgres_sink_inserts_parameterized_row():
    conn = _FakeConn()
    sink = PostgresAuditSink(connection=conn, table="aegis_audit")
    entry = {"seq": 7, "ts": 1.5, "event": "authz.deny",
             "fields": {"perm": "users:read"}, "prev_hash": "0" * 64, "hash": "h" * 64}
    sink(entry)
    inserts = [(sql, p) for sql, p in conn.calls if sql.startswith("INSERT")]
    assert len(inserts) == 1
    sql, params = inserts[0]
    assert "%s" in sql and "ON CONFLICT (hash) DO NOTHING" in sql   # parameterized + idempotent
    assert params[0] == 7 and params[2] == "authz.deny" and params[5] == "h" * 64
    assert json.loads(params[3]) == {"perm": "users:read"}          # fields as JSON
    assert conn.commits >= 1


def test_postgres_sink_rejects_unsafe_table_name():
    with pytest.raises(ValueError):
        PostgresAuditSink(connection=_FakeConn(), table="audit; DROP TABLE users")


def test_postgres_sink_requires_a_target():
    with pytest.raises(ValueError):
        PostgresAuditSink()
