"""Django adapter — the ONLY Django-specific code in AEGIS.

Add one line to ``MIDDLEWARE`` and AEGIS boots (fail-closed) at startup and protects
every request::

    MIDDLEWARE = ["aegis.adapters.django_adapter.AegisMiddleware", ...]

Protect individual views with the decorators::

    from aegis.adapters.django_adapter import require_auth, require_permission, validate_body

    @require_permission("orders:read")
    def list_orders(request): ...
"""
from __future__ import annotations

import json

try:
    from django.conf import settings as dj_settings
    from django.http import HttpResponse, JsonResponse
except Exception as exc:  # pragma: no cover
    raise ImportError(
        "AEGIS Django adapter requires Django. Install with: pip install 'aegis-security[django]'"
    ) from exc

from .. import get_engine
from ..core.context import Identity, RequestContext, ResponseContext
from ..core.exceptions import BootSelfCheckError
from .base import Adapter


# --------------------------------------------------------------------------- #
# View decorators -> declare per-route requirements (deny-by-default authz).
# --------------------------------------------------------------------------- #
def require_auth(view):
    view._aegis_require_auth = True
    return view


def require_permission(*permissions: str):
    def deco(view):
        view._aegis_require_permission = permissions if len(permissions) > 1 else permissions[0]
        view._aegis_require_auth = True
        return view
    return deco


def validate_body(schema):
    def deco(view):
        view._aegis_body_schema = schema
        return view
    return deco


class DjangoAdapter(Adapter):
    def build_context(self, request) -> RequestContext:
        headers = self.normalize_headers(request.headers.items())
        xff = headers.get("x-forwarded-for", "")
        body = None
        ctype = headers.get("content-type", "")
        if "application/json" in ctype and request.body:
            try:
                body = json.loads(request.body.decode("utf-8"))
            except Exception:
                body = None  # validation module will reject if a schema is declared
        return RequestContext(
            method=request.method.upper(),
            path=request.path,
            headers=headers,
            cookies=dict(request.COOKIES),
            query={k: request.GET.get(k) for k in request.GET},
            body=body,
            raw_remote_addr=request.META.get("REMOTE_ADDR", ""),
            forwarded_for=tuple(p.strip() for p in xff.split(",") if p.strip()),
            scheme=request.scheme,
            identity=Identity(),
        )

    def apply_response(self, ctx, resp: ResponseContext, framework_response):
        for name, value in resp.headers.items():
            framework_response[name] = value
        for name, attrs in resp.set_cookies.items():
            framework_response.set_cookie(
                name,
                attrs.get("value", ""),
                max_age=attrs.get("max_age"),
                secure=attrs.get("secure", True),
                httponly=attrs.get("httponly", True),
                samesite=attrs.get("samesite", "Lax"),
                path=attrs.get("path", "/"),
            )
        return framework_response

    def to_django_deny(self, deny: ResponseContext):
        body = deny.body if isinstance(deny.body, dict) else {"error": str(deny.body)}
        response = JsonResponse(body, status=deny.status)
        return response


class AegisMiddleware:
    """The one-line install. Boots AEGIS at startup; protects every request."""

    def __init__(self, get_response):
        self.get_response = get_response
        self.adapter = DjangoAdapter()
        self.engine = get_engine()  # autoboots from env -> fail-closed self-check here
        self._django_safety_check()

    def _django_safety_check(self) -> None:
        # In production, Django DEBUG=True leaks stack traces/settings -> refuse to boot.
        if self.engine.config.is_production and getattr(dj_settings, "DEBUG", False):
            raise BootSelfCheckError(
                "Django DEBUG=True in a production AEGIS environment; refusing to boot."
            )

    def __call__(self, request):
        ctx = self.adapter.build_context(request)
        request._aegis_ctx = ctx
        request._aegis_ran = False

        response = self.get_response(request)

        # If no view ran (e.g. 404), the pipeline never executed in process_view.
        if not getattr(request, "_aegis_ran", False):
            deny = self.engine.handle_request(ctx)
            request._aegis_ran = True
            if deny is not None:
                response = self.adapter.to_django_deny(deny)

        return self._decorate(ctx, response)

    def process_view(self, request, view_func, view_args, view_kwargs):
        ctx = getattr(request, "_aegis_ctx", None)
        if ctx is None:
            return None
        self._load_requirements(ctx, view_func)
        deny = self.engine.handle_request(ctx)
        request._aegis_ran = True
        if deny is not None:
            return self.adapter.to_django_deny(deny)
        return None

    @staticmethod
    def _load_requirements(ctx, view_func) -> None:
        target = getattr(view_func, "view_class", view_func)  # support CBVs
        for src in (view_func, target):
            if getattr(src, "_aegis_require_auth", False):
                ctx.state["require_auth"] = True
            perm = getattr(src, "_aegis_require_permission", None)
            if perm is not None:
                ctx.state["require_permission"] = perm
            schema = getattr(src, "_aegis_body_schema", None)
            if schema is not None:
                ctx.state["body_schema"] = schema

    def _decorate(self, ctx, response):
        rc = ResponseContext(status=getattr(response, "status_code", 200))
        self.engine.handle_response(ctx, rc)
        return self.adapter.apply_response(ctx, rc, response)
