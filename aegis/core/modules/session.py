"""Module 8 — Session & token security (cookies + CSRF).

ASVS V3 · OWASP A01/A07. Issues hardened cookie attributes (httpOnly, Secure,
SameSite) and enforces CSRF on state-changing requests via a signed double-submit
token. Token-authenticated requests (Authorization: Bearer …) carry no ambient
credential and are CSRF-exempt by design.
"""
from __future__ import annotations

from ..crypto import constant_time_compare, hmac_sign, hmac_verify, random_token
from ..exceptions import CsrfError
from .base import Module

CSRF_COOKIE = "aegis_csrf"
CSRF_HEADER = "x-csrf-token"


class SessionModule(Module):
    name = "session"
    asvs = "V3"
    owasp = "A01/A07:2021"
    wraps = "stdlib hmac (signed double-submit)"

    # --- CSRF on unsafe methods ---------------------------------------------
    def process_request(self, ctx) -> None:
        if ctx.method in self.config.csrf_safe_methods:
            return
        # Bearer-token requests are immune to CSRF (no cookie ambient auth).
        if ctx.headers.get("authorization", "").lower().startswith("bearer "):
            return

        cookie = ctx.cookies.get(CSRF_COOKIE, "")
        header = ctx.headers.get(CSRF_HEADER, "")
        if not cookie or not header:
            raise CsrfError("missing CSRF token")
        if not constant_time_compare(cookie, header):
            raise CsrfError("CSRF cookie/header mismatch")
        if not self._valid_signed_token(cookie):
            raise CsrfError("invalid CSRF token signature")

    def _valid_signed_token(self, token: str) -> bool:
        # token = "<random>.<hmac>"
        if "." not in token:
            return False
        body, sig = token.rsplit(".", 1)
        return hmac_verify(self.config.secret_key, body, sig)

    def issue_csrf_token(self) -> str:
        body = random_token(24)
        return f"{body}.{hmac_sign(self.config.secret_key, body)}"

    # --- response: ensure a CSRF cookie + harden Set-Cookie -----------------
    def process_response(self, ctx, resp) -> None:
        if CSRF_COOKIE not in ctx.cookies and CSRF_COOKIE not in resp.set_cookies:
            resp.set_cookies[CSRF_COOKIE] = {
                "value": self.issue_csrf_token(),
                "httponly": False,  # JS must read it to echo into the header
                "secure": self.config.cookie_secure,
                "samesite": self.config.cookie_samesite,
                "path": "/",
                "max_age": self.config.session_ttl,
            }
        # Harden any cookie the app set without explicit flags.
        for attrs in resp.set_cookies.values():
            attrs.setdefault("secure", self.config.cookie_secure)
            attrs.setdefault("samesite", self.config.cookie_samesite)
            attrs.setdefault("path", "/")
