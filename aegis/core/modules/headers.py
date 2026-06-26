"""Module 7 — Security headers + CORS/CSP, and trusted client-IP resolution.

ASVS V14.4/V14.5 · OWASP A05. Strict headers by default (HSTS over TLS, CSP,
X-Frame-Options, etc.). **Boot-refuses** wildcard CORS or 'TLS not expected' in prod.
Also resolves the *vetted* client IP: ``X-Forwarded-For`` is honored ONLY when the
socket peer is a configured trusted proxy (defeats S2 header-spoofing).
"""
from __future__ import annotations

import ipaddress

from ...config.defaults import DEFAULT_SECURITY_HEADERS
from ..exceptions import BootSelfCheckError
from .base import Module

# Headers that leak server internals — stripped from every response.
_LEAKY_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime")


class HeadersModule(Module):
    name = "headers"
    asvs = "V14.4, V14.5"
    owasp = "A05:2021"
    wraps = "orchestration (header policy)"

    def self_check(self) -> None:
        cfg = self.config
        if cfg.is_production:
            if "*" in cfg.cors_allowed_origins:
                raise BootSelfCheckError("Wildcard CORS origin '*' is forbidden in production.")
            for origin in cfg.cors_allowed_origins:
                if not origin.startswith("https://"):
                    raise BootSelfCheckError(f"CORS origin must be https:// in production: {origin!r}")
            if not cfg.require_tls:
                raise BootSelfCheckError("TLS is not expected in production (require_tls=False); refusing to boot.")

    # --- request: resolve the real client IP, safely ------------------------
    def process_request(self, ctx) -> None:
        ctx.client_ip = self._resolve_ip(ctx)

    def _resolve_ip(self, ctx) -> str:
        peer = ctx.raw_remote_addr or ctx.client_ip
        if ctx.forwarded_for and self._is_trusted_proxy(peer):
            # Leftmost entry is the original client when every hop is trusted.
            return ctx.forwarded_for[0]
        # Not behind a trusted proxy -> NEVER trust X-Forwarded-For.
        return peer

    def _is_trusted_proxy(self, peer: str) -> bool:
        if not peer:
            return False
        try:
            addr = ipaddress.ip_address(peer)
        except ValueError:
            return False
        for entry in self.config.trusted_proxies:
            try:
                if "/" in entry:
                    if addr in ipaddress.ip_network(entry, strict=False):
                        return True
                elif addr == ipaddress.ip_address(entry):
                    return True
            except ValueError:
                continue
        return False

    # --- response: harden every outbound response ---------------------------
    def process_response(self, ctx, resp) -> None:
        for name, value in DEFAULT_SECURITY_HEADERS.items():
            resp.headers.setdefault(name, value)
        if self.config.csp:
            resp.headers.setdefault("Content-Security-Policy", self.config.csp)
        if ctx.is_secure:
            resp.headers.setdefault(
                "Strict-Transport-Security",
                f"max-age={self.config.hsts_max_age}; includeSubDomains; preload",
            )
        for leaky in _LEAKY_HEADERS:
            resp.headers.pop(leaky, None)
        self._apply_cors(ctx, resp)

    def _apply_cors(self, ctx, resp) -> None:
        origin = ctx.headers.get("origin")
        if origin and origin in self.config.cors_allowed_origins:
            resp.set_header("Access-Control-Allow-Origin", origin)  # echo specific origin, never "*"
            resp.set_header("Vary", "Origin")
            resp.set_header("Access-Control-Allow-Credentials", "true")
            resp.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
            resp.set_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-CSRF-Token")
            resp.set_header("Access-Control-Max-Age", "600")
        # Disallowed origins get NO CORS headers -> the browser blocks the read.
