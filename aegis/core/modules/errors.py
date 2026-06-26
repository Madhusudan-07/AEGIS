"""Module 12 — Safe error handling.

ASVS V7.4 / V14.3 · OWASP A05. Clients receive a generic message + correlation id;
full detail (and stack traces) go to the internal audit log ONLY. Never leak stack
traces, versions, framework internals, or secret/PII material (redaction applies).
"""
from __future__ import annotations

from ..redaction import redact_value
from .base import Module

_LEAKY_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime", "X-Debug")


class ErrorsModule(Module):
    name = "errors"
    asvs = "V7.4, V14.3"
    owasp = "A05:2021"
    wraps = "orchestration (safe error policy)"

    def process_response(self, ctx, resp) -> None:
        # Strip server-fingerprinting headers from every response.
        for h in _LEAKY_HEADERS:
            resp.headers.pop(h, None)
        # Redact any accidental sensitive content in a string error body.
        if isinstance(resp.body, str):
            resp.body = redact_value(resp.body)

    def safe_response(self, exc: Exception, ctx) -> dict:
        """Build the generic client body for an unhandled application exception.

        The detail is audited internally; the client sees only the correlation id so
        an operator can find the full record without anything leaking on the wire.
        """
        if self.engine.audit:
            self.engine.audit.record(
                "app.unhandled_exception", correlation_id=ctx.correlation_id,
                error_type=type(exc).__name__, path=ctx.path, method=ctx.method,
            )
        return {
            "error": "An internal error occurred.",
            "correlation_id": ctx.correlation_id,
        }
