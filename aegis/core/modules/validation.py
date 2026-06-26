"""Module 3 — Input validation & sanitization / output encoding.

ASVS V5 · OWASP A03 (Injection). The PRIMARY defenses against injection are
parameterized queries (ORM) and context-correct output encoding — documented in the
README; AEGIS cannot retrofit those into the host app's data layer. This module adds
boundary defense-in-depth: reject control-byte smuggling, enforce per-route schemas,
and provide vetted sanitizers/encoders the app calls at trust boundaries.

Wraps: ``bleach`` for HTML sanitization when installed, else a safe stdlib fallback.
"""
from __future__ import annotations

import html
from typing import Any, Iterable, Mapping

from ..exceptions import ValidationFailed
from .base import Module

try:  # vetted HTML sanitizer (optional extra)
    import bleach  # type: ignore
    _HAS_BLEACH = True
except ImportError:  # pragma: no cover
    _HAS_BLEACH = False

_ALLOWED_TAGS = ["b", "i", "em", "strong", "a", "p", "ul", "ol", "li", "br", "code", "pre"]
_ALLOWED_ATTRS = {"a": ["href", "title", "rel"]}


def sanitize_html(value: str) -> str:
    """Neutralize XSS in user-supplied HTML. Prefer encoding over sanitizing when possible."""
    if _HAS_BLEACH:
        return bleach.clean(value, tags=_ALLOWED_TAGS, attributes=_ALLOWED_ATTRS, strip=True)
    # Fallback: full escape (safe, just not rich). Never returns live markup.
    return html.escape(value, quote=True)


def encode_for_html(value: Any) -> str:
    """Context-correct output encoding for HTML text nodes."""
    return html.escape(str(value), quote=True)


def reject_unknown_fields(data: Mapping[str, Any], allowed: Iterable[str]) -> None:
    """Mass-assignment / IDOR guard: refuse bodies carrying fields outside the allow-list."""
    extra = set(data) - set(allowed)
    if extra:
        raise ValidationFailed(f"unknown fields rejected: {sorted(extra)}")


def is_safe_relative_path(path: str) -> bool:
    """Path-traversal guard for user-influenced file paths."""
    return not ("\x00" in path or ".." in path.replace("\\", "/").split("/"))


class ValidationModule(Module):
    name = "validation"
    asvs = "V5"
    owasp = "A03:2021"
    wraps = "bleach (HTML) + stdlib"

    def process_request(self, ctx) -> None:
        # 1. Reject control-byte smuggling in the request line (cheap, high-signal).
        if "\x00" in ctx.path or any("\x00" in str(v) for v in ctx.query.values()):
            raise ValidationFailed("null byte in request")

        # 2. Per-route schema, if the view declared one via @validate_body(schema).
        schema = ctx.state.get("body_schema")
        if schema is not None and ctx.method in ("POST", "PUT", "PATCH"):
            ctx.body = self._validate_body(ctx.body, schema)

    @staticmethod
    def _validate_body(body: Any, schema) -> Any:
        """``schema`` is a callable ``(body) -> cleaned`` (raises on invalid), or a
        ``{field: type}`` mapping. Unknown fields are rejected (deny-by-default)."""
        if callable(schema):
            try:
                return schema(body)
            except ValidationFailed:
                raise
            except Exception as exc:  # any validator error -> generic 400
                raise ValidationFailed(f"schema validation failed: {exc.__class__.__name__}") from exc
        if isinstance(schema, Mapping):
            if not isinstance(body, Mapping):
                raise ValidationFailed("expected an object body")
            reject_unknown_fields(body, schema.keys())
            for field, expected in schema.items():
                if field not in body:
                    raise ValidationFailed(f"missing required field: {field}")
                if not isinstance(body[field], expected):
                    raise ValidationFailed(f"field {field} has wrong type")
            return body
        return body
