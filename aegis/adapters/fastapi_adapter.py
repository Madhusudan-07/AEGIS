"""FastAPI / Starlette adapter — proof that AEGIS is framework-agnostic (Requirement B).

The SAME core engine + 13 modules protect FastAPI through this one thin adapter, with
**zero changes to aegis/core/**. It is written to be *idiomatic to FastAPI*, not a port of
the Django decorator pattern:

* perimeter controls (headers, deception, rate-limit, authn) run in **ASGI middleware** —
  the sync core is bridged onto the event loop via ``run_in_threadpool``;
* per-route **authorization is a dependency** (``Depends``) — the FastAPI-native way to
  declare a requirement — reusing the same core AuthZ module;
* request bodies are validated by **Pydantic** (``extra="forbid"``), so the adapter never
  has to consume the request stream.

One-step connect (Requirement A)::

    app = FastAPI()
    install_aegis(app)                       # <-- the only required line

    @app.get("/admin", dependencies=[Depends(require_permission("users:read"))])
    async def admin(): ...
"""
from __future__ import annotations

from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse

from .. import get_engine
from ..core.context import Identity, RequestContext, ResponseContext
from ..core.exceptions import SecurityViolation
from .base import Adapter

_CTX_KEY = "aegis_ctx"


class FastAPIAdapter(Adapter):
    def build_context(self, request: Request) -> RequestContext:
        headers = self.normalize_headers(request.headers.items())
        xff = headers.get("x-forwarded-for", "")
        return RequestContext(
            method=request.method.upper(),
            path=request.url.path,
            headers=headers,
            cookies=dict(request.cookies),
            query={k: v for k, v in request.query_params.items()},
            body=None,  # Pydantic validates bodies natively; don't consume the stream here
            raw_remote_addr=request.client.host if request.client else "",
            forwarded_for=tuple(p.strip() for p in xff.split(",") if p.strip()),
            scheme=request.url.scheme,
            identity=Identity(),
        )

    def apply_response(self, ctx, resp: ResponseContext, framework_response):
        for name, value in resp.headers.items():
            framework_response.headers[name] = value
        for name, attrs in resp.set_cookies.items():
            framework_response.set_cookie(
                name, attrs.get("value", ""), max_age=attrs.get("max_age"),
                secure=attrs.get("secure", True), httponly=attrs.get("httponly", True),
                samesite=attrs.get("samesite", "lax"), path=attrs.get("path", "/"))
        return framework_response

    def to_deny(self, deny: ResponseContext) -> JSONResponse:
        body = deny.body if isinstance(deny.body, dict) else {"error": str(deny.body)}
        response = JSONResponse(body, status_code=deny.status)
        for name, value in deny.headers.items():
            response.headers[name] = value
        return response


def install_aegis(app):
    """The one-step connect for FastAPI. Adds the AEGIS middleware; boots the engine lazily."""
    adapter = FastAPIAdapter()

    @app.middleware("http")
    async def _aegis(request: Request, call_next):
        engine = get_engine()
        ctx = adapter.build_context(request)
        request.scope[_CTX_KEY] = ctx
        if any(request.url.path.startswith(p) for p in engine.config.exempt_path_prefixes):
            return await call_next(request)
        # Sync core under an async framework -> run the pipeline in a worker thread.
        deny = await run_in_threadpool(engine.handle_request, ctx)
        if deny is not None:
            return adapter.to_deny(deny)
        response = await call_next(request)
        rc = ResponseContext(status=response.status_code)
        engine.handle_response(ctx, rc)
        return adapter.apply_response(ctx, rc, response)

    return app


# --- per-route dependencies (idiomatic FastAPI authorization) ----------------
def _ctx(request: Request) -> RequestContext | None:
    return request.scope.get(_CTX_KEY)


def _http(status: int, detail: str):
    from fastapi import HTTPException
    return HTTPException(status_code=status, detail=detail)


def require_auth(request: Request) -> None:
    ctx = _ctx(request)
    if ctx is None or not ctx.identity.authenticated:
        raise _http(401, "Authentication required.")


def require_permission(*permissions: str):
    """Dependency: deny-by-default RBAC via the same core AuthZ module (no core changes)."""
    def dependency(request: Request) -> None:
        ctx = _ctx(request)
        if ctx is None:
            raise _http(401, "Authentication required.")
        ctx.state["require_permission"] = permissions if len(permissions) > 1 else permissions[0]
        try:
            get_engine().module("authz").process_request(ctx)  # raises on deny
        except SecurityViolation as exc:
            raise _http(exc.status_code, exc.public_message)
    return dependency
