"""Module — Deception / honeypot.  Turns attacker recon into a block signal.

ASVS V11 (anti-automation) · OWASP A09. Decoy paths (``/.env``, ``/.git/config``, …)
are never requested by a legitimate client, so a single hit is a high-confidence probe.
On a hit AEGIS flags the source IP, adds it to a short-TTL blocklist, and **cuts it off
from every endpoint** for the window. It runs early in the pipeline so a flagged attacker
is denied before any real handler is reached.

Advances threat-model gap **G3**: it won't catch a careful low-and-slow attacker who
avoids the decoys — but it cheaply removes the noisy scanners that make up most traffic,
and every hit is audited + alerted. Honest, not magic.
"""
from __future__ import annotations

from ..exceptions import SecurityViolation
from ..stores import StoreUnavailable
from .base import Module


class DeceptionModule(Module):
    name = "deception"
    asvs = "V11"
    owasp = "A09:2021"
    wraps = "redis blocklist / in-memory"

    def process_request(self, ctx) -> None:
        ip = ctx.client_ip or ctx.raw_remote_addr or "unknown"

        # 1. Already trapped? Cut them off — for everything, silently (looks like 404).
        if self._is_blocked(ip):
            self._deny("client on deception blocklist")

        # 2. Touched a decoy path? Flag + blocklist + deny.
        if self._is_honeypot(ctx.path):
            self._flag(ip, ctx.path)
            self._deny(f"honeypot hit: {ctx.path}")

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _deny(detail: str):
        v = SecurityViolation(detail, public_message="Not found.")
        v.status_code = 404  # don't reveal that they tripped a trap or are blocked
        raise v

    def _is_honeypot(self, path: str) -> bool:
        return any(path == p or path.startswith(p.rstrip("/") + "/")
                   for p in self.config.honeypot_paths)

    def _key(self, ip: str) -> str:
        return f"deception:block:{ip}"

    def _is_blocked(self, ip: str) -> bool:
        # Best-effort: if the store is down, don't block (other modules, incl. the
        # fail-closed rate limiter, still apply). Deception is added signal, not the gate.
        try:
            return self.engine.store.get(self._key(ip)) is not None
        except StoreUnavailable:
            return False

    def _flag(self, ip: str, path: str) -> None:
        try:
            self.engine.store.set(self._key(ip), path, ttl=self.config.deception_block_ttl)
        except StoreUnavailable:
            pass
        self.engine.audit.record("deception.honeypot_hit", client_ip=ip, path=path,
                                 outcome="blocked")
        self.engine.alert("deception.attacker_trapped", ip=ip, path=path)
