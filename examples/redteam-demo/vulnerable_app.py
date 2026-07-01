"""SecureNotes API — the NAIVE, UNPROTECTED build.  Serves on http://127.0.0.1:8000

⚠️  This is deliberately insecure, to contrast with secure_app.py. DO NOT copy it.
Every weakness is labelled `# VULN:` so you can diff it against the AEGIS build and see
exactly what changed. It is the "before" in the before/after.
"""
from __future__ import annotations

import base64
import json

from django.conf import settings

if not settings.configured:
    settings.configure(
        DEBUG=True,                       # VULN: leaks stack traces + settings to clients
        SECRET_KEY="insecure-demo-key",   # nosec B106 - deliberately-weak demo
        ALLOWED_HOSTS=["*"],
        ROOT_URLCONF="__main__",
        MIDDLEWARE=[],                    # VULN: no security middleware whatsoever
        DATABASES={},
        USE_TZ=True,
    )

import django  # noqa: E402

django.setup()

from django.http import HttpResponse, JsonResponse  # noqa: E402
from django.urls import path  # noqa: E402
from django.views.decorators.csrf import csrf_exempt  # noqa: E402

# In-memory seed data. VULN: passwords stored in PLAINTEXT.
USERS = {
    "alice": {"password": "password123", "role": "user", "display_name": "Alice"},
    "bob": {"password": "bobs-secret", "role": "user", "display_name": "Bob"},
    "admin": {"password": "admin123", "role": "admin", "display_name": "Admin"},
}
NOTES = {"alice": ["alice's private note"], "bob": ["bob's private note"]}


def _identity(request):
    # VULN: the token is base64("username:role") and the server TRUSTS the role baked
    # into it by the client — so anyone can mint an "admin" token.
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        username, role = base64.b64decode(auth[7:]).decode().split(":")
        return {"username": username, "role": role}
    except Exception:
        return None


def home(request):
    return HttpResponse("SecureNotes [UNPROTECTED] is up")  # VULN: no security headers


@csrf_exempt
def login(request):
    data = json.loads(request.body or b"{}")
    u = USERS.get(data.get("username"))
    # VULN: plaintext password compare, no rate limit, no lockout -> brute-forceable.
    if u and u["password"] == data.get("password"):
        token = base64.b64encode(f"{data['username']}:{u['role']}".encode()).decode()
        return JsonResponse({"token": token})
    return JsonResponse({"error": "invalid credentials"}, status=401)


def notes(request):
    ident = _identity(request)
    if not ident:
        return JsonResponse({"error": "auth required"}, status=401)
    return JsonResponse({"notes": NOTES.get(ident["username"], [])})


def admin_users(request):
    ident = _identity(request)
    if not ident:
        return JsonResponse({"error": "auth required"}, status=401)
    # VULN: broken access control — authenticated but NO authorization check.
    # Any logged-in user (or a forged token) can list every account.
    return JsonResponse({"users": list(USERS.keys())})


@csrf_exempt
def profile(request):
    ident = _identity(request)
    if not ident:
        return JsonResponse({"error": "auth required"}, status=401)
    data = json.loads(request.body or b"{}")
    # VULN: mass assignment — blindly applies every field, so a client can set
    # role/is_admin on itself.
    USERS[ident["username"]].update(data)
    return JsonResponse({"profile": USERS[ident["username"]]})


def fetch(request):
    import urllib.request

    url = request.GET.get("url", "")
    # VULN: fetches whatever URL the client supplies -> SSRF (internal services, cloud
    # metadata at 169.254.169.254, etc. are all reachable).
    try:
        with urllib.request.urlopen(url, timeout=3) as r:  # nosec B310 - deliberately vulnerable
            return JsonResponse({"fetched": url, "preview": r.read(120).decode("utf-8", "replace")})
    except Exception as exc:
        return JsonResponse({"fetched": url, "error": str(exc)}, status=502)


urlpatterns = [
    path("", home),
    path("login", login),
    path("notes", notes),
    path("admin/users", admin_users),
    path("profile", profile),
    path("fetch", fetch),
]


if __name__ == "__main__":
    from socketserver import ThreadingMixIn
    from wsgiref.simple_server import WSGIServer, make_server

    from django.core.wsgi import get_wsgi_application

    class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):  # concurrent, like a real server
        daemon_threads = True

    print("SecureNotes [UNPROTECTED] on http://127.0.0.1:8000")
    make_server("127.0.0.1", 8000, get_wsgi_application(),
                server_class=ThreadingWSGIServer).serve_forever()
