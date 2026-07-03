"""Durable audit sinks — persist the hash-chained audit trail beyond process memory.

ASVS V7 (logging) · spec principle 10 (auditability). :class:`~aegis.core.modules.audit.AuditLog`
keeps a bounded in-memory ring for live verification; a **sink** (``callable(entry) -> None``)
is where history is meant to live durably. This module supplies two ready sinks and a
combinator:

* :class:`FileAuditSink`     — append-only JSONL. Zero dependencies, survives restarts.
* :class:`PostgresAuditSink` — append-only table (wraps ``psycopg``). Production history.
* :func:`fan_out`            — feed one entry to many sinks (e.g. live EventStream **and**
                               durable storage) with per-sink isolation.

Every entry already arrives **redacted** (secrets/PII stripped by ``AuditLog.record``), so a
sink only persists — it never has to sanitize. The chain's ``prev_hash``/``hash`` columns make
stored history independently tamper-evident: re-run the same verification over any window.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

# The columns every sink persists — the exact tuple AuditLog hashes over, plus the hash.
_FIELDS = ("seq", "ts", "event", "fields", "prev_hash", "hash")


class FileAuditSink:
    """Append each audit entry as one JSON line (JSONL). Durable, dependency-free.

    Append-only + line-buffered flush: a crash can at worst lose the final unflushed line,
    never corrupt earlier history. Thread-safe; safe to point many request threads at one
    file. Re-opening the same path on restart continues the same trail (verify with
    :meth:`read_all`).
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def __call__(self, entry: dict) -> None:
        line = json.dumps({k: entry.get(k) for k in _FIELDS}, default=str, separators=(",", ":"))
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()

    def read_all(self) -> list[dict]:
        """Load the persisted entries (oldest-first) — for verification / inspection."""
        if not self.path.exists():
            return []
        with self._lock, self.path.open("r", encoding="utf-8") as fh:
            return [json.loads(ln) for ln in fh if ln.strip()]


class PostgresAuditSink:
    """Append audit entries to a Postgres table (wraps ``psycopg``).

    The table is append-only by contract (INSERT-only; no UPDATE/DELETE path). ``fields`` is
    stored as JSONB; ``prev_hash``/``hash`` let you re-verify the chain in SQL or on export.
    Pass a DSN (a real connection is opened lazily) or inject an existing DBAPI ``connection``
    (tests, or an app that manages its own pool).
    """

    _DDL = (
        "CREATE TABLE IF NOT EXISTS {table} ("
        "  seq BIGINT NOT NULL,"
        "  ts DOUBLE PRECISION NOT NULL,"
        "  event TEXT NOT NULL,"
        "  fields JSONB NOT NULL,"
        "  prev_hash CHAR(64) NOT NULL,"
        "  hash CHAR(64) NOT NULL PRIMARY KEY"  # hash is unique -> natural idempotency
        ")"
    )
    _INSERT = (
        "INSERT INTO {table} (seq, ts, event, fields, prev_hash, hash)"
        " VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (hash) DO NOTHING"
    )

    def __init__(self, dsn: str | None = None, *, connection=None, table: str = "aegis_audit"):
        if not (dsn or connection):
            raise ValueError("PostgresAuditSink needs a dsn or an existing connection")
        if not table.isidentifier():
            raise ValueError(f"unsafe table name: {table!r}")  # table can't be parameterized
        self._table = table
        self._lock = threading.Lock()
        self._conn = connection
        self._dsn = dsn
        self._ready = False
        if connection is not None:
            self._ensure_schema()

    def _connect(self):
        if self._conn is None:
            import psycopg  # optional dependency
            self._conn = psycopg.connect(self._dsn)
        return self._conn

    def _ensure_schema(self) -> None:
        if self._ready:
            return
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute(self._DDL.format(table=self._table))
        conn.commit()
        self._ready = True

    def __call__(self, entry: dict) -> None:
        with self._lock:
            self._ensure_schema()
            conn = self._connect()
            with conn.cursor() as cur:
                cur.execute(
                    self._INSERT.format(table=self._table),
                    (entry.get("seq"), entry.get("ts"), entry.get("event"),
                     json.dumps(entry.get("fields", {}), default=str),
                     entry.get("prev_hash"), entry.get("hash")),
                )
            conn.commit()


def fan_out(*sinks):
    """Combine sinks into one callable that feeds each the same entry.

    Isolation: **every** sink is attempted even if an earlier one fails, so one bad sink
    can't starve the others. Visibility: the first failure is re-raised afterwards, so
    ``AuditLog.record`` still logs an ``audit.sink_failure`` — a broken durable sink is
    never swallowed silently. ``None`` sinks are ignored (convenient for optional wiring).
    """
    active = [s for s in sinks if s is not None]

    def _sink(entry: dict) -> None:
        first_error: Exception | None = None
        for s in active:
            try:
                s(entry)
            except Exception as exc:  # noqa: BLE001 - attempt the rest, surface the first
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise first_error

    return _sink
