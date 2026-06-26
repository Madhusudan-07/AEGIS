"""Ephemeral AEGIS-protected Django instance for DAST live-probing.

THROWAWAY, dev-mode only — never deploy this. It exists so the daily battery can attack
a running instance. Run: ``AEGIS_ENV=development python examples/demo_app/server.py``
"""
from __future__ import annotations

import os

os.environ.setdefault("AEGIS_ENV", "development")

from django.conf import settings  # noqa: E402

if not settings.configured:
    settings.configure(
        DEBUG=False,                       # never True (AEGIS would refuse to boot in prod)
        SECRET_KEY="django-dev-only-throwaway",  # nosec B106 - throwaway dev instance
        ALLOWED_HOSTS=["*"],
        ROOT_URLCONF="__main__",
        MIDDLEWARE=["aegis.adapters.django_adapter.AegisMiddleware"],
        DATABASES={},
        USE_TZ=True,
    )

import django  # noqa: E402

django.setup()

from django.http import HttpResponse, JsonResponse  # noqa: E402
from django.urls import path  # noqa: E402

import aegis  # noqa: E402
from aegis.adapters.django_adapter import require_permission  # noqa: E402
from aegis.core.config import AegisConfig  # noqa: E402
from aegis.core.crypto import generate_field_key  # noqa: E402
from aegis.core.policy import Policy  # noqa: E402

# Boot AEGIS (dev mode) before serving so the middleware reuses this engine + policy.
aegis.reset_engine()
aegis.secure(
    AegisConfig(environment="development", secret_key="d" * 48,
                field_encryption_key=generate_field_key()),
    policy=Policy().grant("admin", "orders:*"),
)


def public(request):
    return HttpResponse("ok")


@require_permission("orders:read")
def orders(request):
    return JsonResponse({"orders": []})


urlpatterns = [path("", public), path("orders", orders)]


if __name__ == "__main__":
    import wsgiref.simple_server as wss

    from django.core.wsgi import get_wsgi_application

    # AEGIS strips fingerprint headers from the *application* response, but the HTTP
    # server below the WSGI boundary advertises its own version. In production you
    # suppress this at gunicorn/nginx; here we do the equivalent at the dev server so
    # DAST probes AEGIS, not wsgiref. (See README -> Limitations: WSGI-app-layer boundary.)
    wss.ServerHandler.server_software = ""

    app = get_wsgi_application()
    print("AEGIS demo serving on http://127.0.0.1:8000")
    wss.make_server("127.0.0.1", 8000, app).serve_forever()
