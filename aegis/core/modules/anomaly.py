"""Module 10 — Anomaly detection & alerting.

ASVS V7.2 · OWASP A09. Heuristic signals only (threshold/velocity), routed to
developer-configured sinks via ``engine.alert`` — **never** phoned home (Principle 7).
Detects auth-failure spikes per identity and per IP. Geo/velocity correlation is a
documented GAP (see THREAT_MODEL G3), not silently claimed.
"""
from __future__ import annotations

from ..stores import StoreUnavailable
from .base import Module


class AnomalyModule(Module):
    name = "anomaly"
    asvs = "V7.2"
    owasp = "A09:2021"
    wraps = "redis counters / in-memory"

    def observe_auth_failure(self, identifier: str, ip: str) -> None:
        window = self.config.anomaly_window
        threshold = self.config.anomaly_authfail_threshold
        for scope, value in (("id", identifier), ("ip", ip or "unknown")):
            try:
                count = self.engine.store.incr(f"anom:authfail:{scope}:{value}", window)
            except StoreUnavailable:
                continue  # detection is best-effort; absence is itself logged elsewhere
            if count == threshold:  # alert once at the crossing, not on every hit after
                self.engine.alert(
                    "anomaly.auth_failure_spike",
                    scope=scope, value=value, count=count, window_seconds=window,
                )

    def observe_authz_denials(self, subject: str) -> None:
        window = self.config.anomaly_window
        try:
            count = self.engine.store.incr(f"anom:authz:{subject}", window)
        except StoreUnavailable:
            return
        if count == self.config.anomaly_authfail_threshold:
            self.engine.alert("anomaly.authz_denial_spike", subject=subject, count=count)
