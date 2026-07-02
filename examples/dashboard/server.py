"""AEGIS live security dashboard — watch attacks get blocked in real time.

Boots the AEGIS-protected SecureNotes API AND an observability plane on the same server:
  /                     protected app (attackable)
  /login /admin/users /profile /fetch   protected endpoints
  /_aegis/              the dashboard (single HTML file)
  /_aegis/events        Server-Sent Events — every security event, live
  /_aegis/stats         JSON snapshot (counters + audit-chain status)

The dashboard's own routes are under an EXEMPT prefix, so firing the red team (which the
browser does client-side) — including the honeypot that blocklists the local IP — never
takes the dashboard itself offline.

Run:  python examples/dashboard/server.py   (or run_dashboard.py to also open the browser)
"""
from __future__ import annotations

import json
import os
import queue
from pathlib import Path

os.environ.setdefault("AEGIS_ENV", "development")

from django.conf import settings

if not settings.configured:
    settings.configure(
        DEBUG=False,
        SECRET_KEY="django-demo-key",  # nosec B106 - throwaway; AEGIS holds the real secret
        ALLOWED_HOSTS=["*"],
        ROOT_URLCONF="__main__",
        MIDDLEWARE=["aegis.adapters.django_adapter.AegisMiddleware"],
        DATABASES={},
        USE_TZ=True,
    )

import django  # noqa: E402

django.setup()

from django.http import HttpResponse, JsonResponse, StreamingHttpResponse  # noqa: E402
from django.urls import path  # noqa: E402

import aegis  # noqa: E402
from aegis import EventStream  # noqa: E402
from aegis.adapters.django_adapter import require_auth, require_permission, validate_body  # noqa: E402
from aegis.core.config import AegisConfig  # noqa: E402
from aegis.core.crypto import generate_field_key  # noqa: E402
from aegis.core.exceptions import SecurityViolation  # noqa: E402
from aegis.core.policy import Policy  # noqa: E402

HERE = Path(__file__).resolve().parent
STREAM = EventStream(capacity=500)  # <- the observability seam

POLICY = (
    Policy()
    .grant("admin", "users:read", "notes:read", "notes:write", "profile:write")
    .grant("user", "notes:read", "notes:write", "profile:write")
)
CONFIG = AegisConfig(
    environment="development",
    secret_key="k" * 48,
    field_encryption_key=generate_field_key(),
    rate_limit_per_ip=(50, 60),
    auth_rate_limit=(50, 60),
    lockout_threshold=5,
    deception_block_ttl=90,            # short so demo re-runs recover
    egress_allow_http=True,
    exempt_path_prefixes=("/_aegis/",),  # the dashboard is never rate-limited/blocked
    enabled_modules=(
        "secrets", "headers", "deception", "ratelimit", "authn", "authz",
        "validation", "encryption", "audit", "anomaly", "errors",
    ),
)

aegis.reset_engine()
# audit_sink -> the stream: EVERY security event (deny/alert/honeypot/auth) becomes live.
HANDLE = aegis.secure(CONFIG, policy=POLICY, audit_sink=STREAM.publish)
ENGINE = HANDLE.engine

USERS = {
    "alice": {"pw": ENGINE.hash_password("password123"), "role": "user", "display_name": "Alice"},
    "bob": {"pw": ENGINE.hash_password("bobs-secret"), "role": "user", "display_name": "Bob"},
    "admin": {"pw": ENGINE.hash_password("admin123"), "role": "admin", "display_name": "Admin"},
}
NOTES = {"alice": ["alice's private note"], "bob": ["bob's private note"]}


def _subject(request):
    ctx = getattr(request, "_aegis_ctx", None)
    return ctx.identity.subject if (ctx and ctx.identity.authenticated) else None


# --- the protected (attackable) app ----------------------------------------
def home(request):
    return HttpResponse("SecureNotes [AEGIS-protected] is up")


def login(request):
    data = json.loads(request.body or b"{}")
    username, password = data.get("username", ""), data.get("password", "")
    user = USERS.get(username)
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


@require_permission("users:read")
def admin_users(request):
    return JsonResponse({"users": list(USERS.keys())})


@require_auth
@validate_body({"display_name": str})
def profile(request):
    body = request._aegis_ctx.body
    USERS[_subject(request)]["display_name"] = body["display_name"]
    return JsonResponse({"profile": {"display_name": body["display_name"]}})


def fetch(request):
    import urllib.parse
    import urllib.request
    url = request.GET.get("url", "")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return JsonResponse({"error": "invalid url"}, status=400)
    try:
        ENGINE.check_egress(parsed.geturl())
    except SecurityViolation as exc:
        return JsonResponse({"error": exc.public_message}, status=exc.status_code)
    try:
        with urllib.request.urlopen(parsed.geturl(), timeout=3) as r:  # nosec B310 - egress-guarded
            return JsonResponse({"fetched": url, "preview": r.read(120).decode("utf-8", "replace")})
    except Exception:
        return JsonResponse({"error": "upstream fetch failed"}, status=502)


# --- the observability plane (EXEMPT prefix) -------------------------------
def dashboard(request):
    return HttpResponse((HERE / "dashboard.html").read_text(encoding="utf-8"))


def sse_events(request):
    q = STREAM.subscribe()

    def gen():
        try:
            for entry in STREAM.recent(60):        # backlog first
                yield f"data: {json.dumps(entry, default=str)}\n\n"
            while True:
                try:
                    entry = q.get(timeout=15)
                    yield f"data: {json.dumps(entry, default=str)}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"          # keep the connection warm
        finally:
            STREAM.unsubscribe(q)

    resp = StreamingHttpResponse(gen(), content_type="text/event-stream")
    resp["Cache-Control"] = "no-cache"
    resp["X-Accel-Buffering"] = "no"
    return resp


def api_stats(request):
    s = STREAM.stats()
    s["chain_ok"] = ENGINE.audit.verify_chain()
    s["audit_entries"] = len(ENGINE.audit.entries)
    return JsonResponse(s)


urlpatterns = [
    path("", home),
    path("login", login),
    path("notes", notes),
    path("admin/users", admin_users),
    path("profile", profile),
    path("fetch", fetch),
    path("_aegis/", dashboard),
    path("_aegis/events", sse_events),
    path("_aegis/stats", api_stats),
]


if __name__ == "__main__":
    import wsgiref.simple_server as wss
    from socketserver import ThreadingMixIn

    from django.core.wsgi import get_wsgi_application

    class ThreadingWSGIServer(ThreadingMixIn, wss.WSGIServer):
        daemon_threads = True

    wss.ServerHandler.server_software = ""
    print("AEGIS dashboard:  http://127.0.0.1:8008/_aegis/")
    wss.make_server("127.0.0.1", 8008, get_wsgi_application(),
                    server_class=ThreadingWSGIServer).serve_forever()
