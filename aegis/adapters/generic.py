"""Generic adapter — proves the core is framework-agnostic.

Use it from any Python entrypoint (a worker, a CLI, a microframework) by passing
primitive request data; you get back either a deny :class:`ResponseContext` or None.
"""
from __future__ import annotations

from ..core.context import Identity, RequestContext, ResponseContext
from .base import Adapter


class GenericAdapter(Adapter):
    def build_context(self, request: dict) -> RequestContext:
        headers = self.normalize_headers((request.get("headers") or {}).items())
        xff = headers.get("x-forwarded-for", "")
        return RequestContext(
            method=request.get("method", "GET").upper(),
            path=request.get("path", "/"),
            headers=headers,
            cookies=dict(request.get("cookies") or {}),
            query=dict(request.get("query") or {}),
            body=request.get("body"),
            raw_remote_addr=request.get("remote_addr", ""),
            forwarded_for=tuple(p.strip() for p in xff.split(",") if p.strip()),
            scheme=request.get("scheme", "http"),
            identity=Identity(),
        )

    def apply_response(self, ctx, resp: ResponseContext, framework_response=None):
        # Generic consumers just read the ResponseContext directly.
        return resp


def protect(engine, request: dict):
    """Run the AEGIS pipeline over a primitive request dict.

    Returns a deny :class:`ResponseContext` (with status/body/headers) if the request
    is rejected, else ``None`` (caller proceeds to its own handler).
    """
    adapter = GenericAdapter()
    ctx = adapter.build_context(request)
    deny = engine.handle_request(ctx)
    if deny is not None:
        return deny
    return None
