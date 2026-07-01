"""SecureNotes API — the AEGIS-PROTECTED build.  Serves on http://127.0.0.1:8001

Same features as vulnerable_app.py, built the right way with AEGIS. Diff the two files:
the security is not scattered through the handlers — it's the middleware plus a few
declarative decorators. The business logic stays clean.
"""
from __future__ import annotations

import json
import os

os.environ.setdefault("AEGIS_ENV", "development")

from django.conf import settings

if not settings.configured:
    settings.configure(
        DEBUG=False,                      # never leak internals (AEGIS refuses prod+DEBUG)
        SECRET_KEY="django-demo-key",     # nosec B106 - throwaway; AEGIS holds the real secret
        ALLOWED_HOSTS=["*"],
        ROOT_URLCONF="__main__",
        MIDDLEWARE=["aegis.adapters.django_adapter.AegisMiddleware"],  # <-- the one line
        DATABASES={},
        USE_TZ=True,
    )

import django  # noqa: E402

django.setup()

from django.http import HttpResponse, JsonResponse  # noqa: E402
from django.urls import path  # noqa: E402

import aegis  # noqa: E402
from aegis.adapters.django_adapter import require_auth, require_permission, validate_body  # noqa: E402
from aegis.core.config import AegisConfig  # noqa: E402
from aegis.core.crypto import generate_field_key  # noqa: E402
from aegis.core.exceptions import SecurityViolation  # noqa: E402
from aegis.core.policy import Policy  # noqa: E402

# Least-privilege policy (deny-by-default is the engine's baseline; this only GRANTS).
POLICY = (
    Policy()
    .grant("admin", "users:read", "notes:read", "notes:write", "profile:write")
    .grant("user", "notes:read", "notes:write", "profile:write")
)

# This is a Bearer-token JSON API, so the session/CSRF module is intentionally off:
# CSRF defends cookie-based flows, and enabling it here would only mislead. Rate-limit
# thresholds are tightened so the demo trips them visibly.
CONFIG = AegisConfig(
    environment="development",
    secret_key="k" * 48,
    field_encryption_key=generate_field_key(),
    rate_limit_per_ip=(200, 60),      # the flood defense (harness fires 250)
    auth_rate_limit=(50, 60),         # loose enough not to mask the lockout below
    lockout_threshold=5,              # the brute-force defense
    egress_allow_http=True,           # demo fetches http:// internal targets -> block on the IP
    enabled_modules=(
        "secrets", "headers", "deception", "ratelimit", "authn", "authz",
        "validation", "encryption", "audit", "anomaly", "errors",
    ),
)

aegis.reset_engine()
HANDLE = aegis.secure(CONFIG, policy=POLICY)
ENGINE = HANDLE.engine

# Users with ARGON2id-hashed passwords (never plaintext), plus roles.
USERS = {
    "alice": {"pw": ENGINE.hash_password("password123"), "role": "user", "display_name": "Alice"},
    "bob": {"pw": ENGINE.hash_password("bobs-secret"), "role": "user", "display_name": "Bob"},
    "admin": {"pw": ENGINE.hash_password("admin123"), "role": "admin", "display_name": "Admin"},
}
NOTES = {"alice": ["alice's private note"], "bob": ["bob's private note"]}


def _subject(request) -> str | None:
    ctx = getattr(request, "_aegis_ctx", None)
    return ctx.identity.subject if (ctx and ctx.identity.authenticated) else None


def home(request):
    return HttpResponse("SecureNotes [AEGIS-protected] is up")


def login(request):
    data = json.loads(request.body or b"{}")
    username, password = data.get("username", ""), data.get("password", "")
    user = USERS.get(username)
    # Enumeration-safe: call login the same way for unknown users (empty decoy hash).
    stored = user["pw"] if user else ""
    roles = (user["role"],) if user else ()
    try:
        token = ENGINE.login(username, password, stored,
                             ip=request.META.get("REMOTE_ADDR", ""), roles=roles)
    except SecurityViolation as exc:
        return JsonResponse({"error": exc.public_message}, status=exc.status_code)
    return JsonResponse({"token": token})


@require_permission("notes:read")
def notes(request):
    return JsonResponse({"notes": NOTES.get(_subject(request), [])})


@require_permission("users:read")  # deny-by-default: only roles granted users:read pass
def admin_users(request):
    return JsonResponse({"users": list(USERS.keys())})


@require_auth
@validate_body({"display_name": str})  # rejects unknown fields -> no mass assignment
def profile(request):
    body = request._aegis_ctx.body
    USERS[_subject(request)]["display_name"] = body["display_name"]
    return JsonResponse({"profile": {"display_name": body["display_name"]}})


def fetch(request):
    # A "link preview" feature — a classic SSRF surface. The egress guard validates the
    # target BEFORE any request is made, so it can't be pointed at internal services.
    import urllib.request

    url = request.GET.get("url", "")
    try:
        ENGINE.check_egress(url)                       # <-- the SSRF guard (closes G2)
    except SecurityViolation as exc:
        return JsonResponse({"error": exc.public_message}, status=exc.status_code)
    try:
        with urllib.request.urlopen(url, timeout=3) as r:  # nosec B310 - egress-guarded above
            return JsonResponse({"fetched": url, "preview": r.read(120).decode("utf-8", "replace")})
    except Exception:
        # Safe error handling: a generic message to the client, never the exception text.
        return JsonResponse({"error": "upstream fetch failed"}, status=502)


urlpatterns = [
    path("", home),
    path("login", login),
    path("notes", notes),
    path("admin/users", admin_users),
    path("profile", profile),
    path("fetch", fetch),
]


if __name__ == "__main__":
    import wsgiref.simple_server as wss
    from socketserver import ThreadingMixIn

    from django.core.wsgi import get_wsgi_application

    class ThreadingWSGIServer(ThreadingMixIn, wss.WSGIServer):  # concurrent, like a real server
        daemon_threads = True

    wss.ServerHandler.server_software = ""  # don't advertise the server version
    print("SecureNotes [AEGIS-protected] on http://127.0.0.1:8001")
    wss.make_server("127.0.0.1", 8001, get_wsgi_application(),
                    server_class=ThreadingWSGIServer).serve_forever()
