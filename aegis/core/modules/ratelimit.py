"""Module 4 — Rate limiting & abuse prevention.

ASVS V11.1 / V2.2 · OWASP A04/A07. Fixed-window counters in Redis (or in-memory for
dev). Per-IP global limit + a much tighter limit on auth paths. Per-identity lockout
lives in :mod:`aegis.core.modules.authn`. **Fail-closed**: if the store is configured
but unreachable and ``fail_closed_on_store_error`` is set, the request is DENIED.
"""
from __future__ import annotations

from ..exceptions import RateLimitExceeded, SecurityViolation
from ..stores import StoreUnavailable
from .base import Module


class RateLimitModule(Module):
    name = "ratelimit"
    asvs = "V11.1, V2.2"
    owasp = "A04/A07:2021"
    wraps = "redis (rate-limiter pattern) / in-memory"

    def process_request(self, ctx) -> None:
        cfg = self.config
        ip = ctx.client_ip or ctx.raw_remote_addr or "unknown"

        # Global per-IP limit.
        limit, window = cfg.rate_limit_per_ip
        self._enforce(f"rl:ip:{ip}", limit, window)

        # Tighter limit on authentication paths (brute-force / credential stuffing).
        if any(ctx.path.startswith(p) for p in cfg.auth_path_prefixes):
            a_limit, a_window = cfg.auth_rate_limit
            self._enforce(f"rl:auth:{ip}", a_limit, a_window)

    def _enforce(self, key: str, limit: int, window: int) -> None:
        store = self.engine.store
        try:
            count = store.incr(key, window)
        except StoreUnavailable as exc:
            if self.config.fail_closed_on_store_error:
                v = SecurityViolation(f"rate-limit store unavailable: {exc}",
                                      public_message="Service temporarily unavailable.")
                v.status_code = 503
                raise v from exc
            return  # explicit opt-in to fail-open (dev only)
        if count > limit:
            ttl = self._safe_ttl(key, window)
            raise RateLimitExceeded(f"limit {limit}/{window}s exceeded on {key}", retry_after=ttl)

    def _safe_ttl(self, key: str, window: int) -> int:
        try:
            return self.engine.store.ttl(key) or window
        except StoreUnavailable:
            return window
