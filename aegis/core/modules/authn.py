"""Module 1 — Authentication.

ASVS V2/V3 · OWASP A07. Per request: verify a Bearer JWT (vetted PyJWT, alg pinned,
``none`` rejected) and populate identity; a *present-but-invalid* credential is denied
401. Login: Argon2id verification + per-identity lockout with exponential backoff +
enumeration-safe responses. Feeds the anomaly module on every failure.
"""
from __future__ import annotations

from ..crypto import verify_password
from ..exceptions import AuthenticationError, SecurityViolation
from ..stores import StoreUnavailable
from .base import Module

_FAIL_WINDOW = 900  # 15 min window for counting consecutive failures
_MAX_BACKOFF = 3600  # cap lockout at 1 hour


class AuthnModule(Module):
    name = "authn"
    asvs = "V2, V3"
    owasp = "A07:2021"
    wraps = "PyJWT (verify) + argon2-cffi (passwords)"

    # --- per-request bearer verification ------------------------------------
    def process_request(self, ctx) -> None:
        token = self._bearer(ctx)
        if token:
            payload = self.engine.tokens.verify(token, expected_type="access")  # raises -> 401
            ctx.identity.subject = payload.get("sub")
            ctx.identity.roles = tuple(payload.get("roles", ()))
            ctx.identity.claims = payload
            ctx.identity.authenticated = True

        # Routes that explicitly require auth (set by @require_auth) must have identity.
        if ctx.state.get("require_auth") and not ctx.identity.authenticated:
            raise AuthenticationError("authentication required for protected route")

    @staticmethod
    def _bearer(ctx) -> str | None:
        header = ctx.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            return header[7:].strip()
        return None

    # --- login + lockout (called by Engine.login) ---------------------------
    def login(self, identifier: str, password: str, stored_hash: str, *, ip: str = "") -> bool:
        if self.is_locked_out(identifier):
            self.engine.alert("auth.lockout_active", identifier=identifier, ip=ip)
            v = AuthenticationError("account temporarily locked",
                                    public_message="Too many attempts. Please try again later.")
            v.status_code = 429
            raise v
        if stored_hash and verify_password(stored_hash, password):
            self.clear_failures(identifier)
            self.engine.audit.record("auth.login_success", subject=identifier, client_ip=ip)
            return True
        self._record_failure(identifier, ip)
        # Identical message + work whether the user exists or not (no enumeration).
        raise AuthenticationError("invalid credentials",
                                  public_message="Invalid email or password.")

    def is_locked_out(self, identifier: str) -> bool:
        try:
            return self.engine.store.get(f"lockout:{identifier}") is not None
        except StoreUnavailable as exc:
            if self.config.fail_closed_on_store_error:
                v = SecurityViolation(f"lockout store unavailable: {exc}",
                                      public_message="Service temporarily unavailable.")
                v.status_code = 503
                raise v from exc
            return False

    def clear_failures(self, identifier: str) -> None:
        try:
            self.engine.store.set(f"authfail:{identifier}", "0", ttl=1)
            self.engine.store.set(f"lockout:{identifier}", "", ttl=1)
        except StoreUnavailable:
            pass

    def _record_failure(self, identifier: str, ip: str) -> None:
        store = self.engine.store
        try:
            count = store.incr(f"authfail:{identifier}", _FAIL_WINDOW)
        except StoreUnavailable:
            count = self.config.lockout_threshold  # can't count -> assume worst, lock
        self.engine.audit.record("auth.login_failure", subject=identifier, client_ip=ip, count=count)
        anomaly = self.engine.module("anomaly")
        if anomaly is not None:
            anomaly.observe_auth_failure(identifier, ip)
        if count >= self.config.lockout_threshold:
            over = count - self.config.lockout_threshold
            backoff = min(self.config.lockout_base_seconds * (2 ** over), _MAX_BACKOFF)
            try:
                store.set(f"lockout:{identifier}", "1", ttl=backoff)
            except StoreUnavailable:
                pass
            self.engine.audit.record("auth.lockout_set", subject=identifier,
                                     seconds=backoff, client_ip=ip)
            self.engine.alert("auth.lockout", identifier=identifier, ip=ip, seconds=backoff)
