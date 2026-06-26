"""Module 9 — Audit logging. Tamper-evident, append-only, redacted.

ASVS V7 (Logging) · OWASP A09 (Security Logging & Monitoring Failures).
Wraps: stdlib hashlib (no hand-rolled crypto). Each entry carries ``prev_hash`` and a
SHA-256 ``hash`` over (seq, ts, event, fields, prev_hash) — editing or deleting any
past entry breaks the chain, which :meth:`AuditLog.verify_chain` detects.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time

from ..redaction import redact
from .base import Module

GENESIS = "0" * 64


class AuditLog:
    """The append-only hash chain. Held by the engine; usable as a service."""

    def __init__(self, sink=None, enabled: bool = True, keep_in_memory: int = 10000):
        self.enabled = enabled
        self.sink = sink                      # callable(entry: dict) -> None (e.g. write to Postgres)
        self._prev = GENESIS
        self._lock = threading.Lock()
        self._chain: list[dict] = []
        self._keep = keep_in_memory

    @staticmethod
    def _hash(entry: dict) -> str:
        material = json.dumps(
            {k: entry[k] for k in ("seq", "ts", "event", "fields", "prev_hash")},
            sort_keys=True, default=str, separators=(",", ":"),
        )
        return hashlib.sha256(material.encode()).hexdigest()

    def record(self, event: str, **fields) -> dict | None:
        if not self.enabled:
            return None
        with self._lock:
            entry = {
                "seq": len(self._chain),
                "ts": time.time(),
                "event": event,
                "fields": redact(fields),  # secrets/PII stripped before persistence
                "prev_hash": self._prev,
            }
            entry["hash"] = self._hash(entry)
            self._prev = entry["hash"]
            self._chain.append(entry)
            if len(self._chain) > self._keep:
                # in-memory ring; durable history is the sink's job. Chain head moves
                # forward but verification of the retained window still holds.
                self._chain = self._chain[-self._keep:]
        if self.sink is not None:
            try:
                self.sink(entry)
            except Exception:
                # A failing sink must not crash the app, but the gap is itself audited.
                self._record_sink_failure(event)
        return entry

    def _record_sink_failure(self, original_event: str) -> None:
        with self._lock:
            entry = {
                "seq": len(self._chain), "ts": time.time(),
                "event": "audit.sink_failure", "fields": {"for": original_event},
                "prev_hash": self._prev,
            }
            entry["hash"] = self._hash(entry)
            self._prev = entry["hash"]
            self._chain.append(entry)

    def verify_chain(self) -> bool:
        """True iff no retained entry has been tampered with or reordered."""
        prev = self._chain[0]["prev_hash"] if self._chain else GENESIS
        for e in self._chain:
            if e["prev_hash"] != prev or e["hash"] != self._hash(e):
                return False
            prev = e["hash"]
        return True

    @property
    def entries(self) -> list[dict]:
        return list(self._chain)


class AuditModule(Module):
    name = "audit"
    asvs = "V7"
    owasp = "A09:2021"
    wraps = "stdlib hashlib (SHA-256 chain)"

    def self_check(self) -> None:
        # Nothing unsafe to detect; presence of the chain is the control.
        return None
