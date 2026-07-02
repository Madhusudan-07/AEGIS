"""SecureNotes on FastAPI — protected by AEGIS via one adapter (Phase 4).

The SAME core engine that protects the Django demo protects this FastAPI app. The only
security wiring is ``install_aegis(app)`` plus a few ``Depends(require_permission(...))``.
Diff this against the Django ``secure_app.py``: different framework, identical defenses.

Run:  python examples/fastapi-demo/app.py     (serves on http://127.0.0.1:8009)
"""
from __future__ import annotations

import os
import urllib.parse
import urllib.request

os.environ.setdefault("AEGIS_ENV", "development")

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict

import aegis
from aegis.adapters.fastapi_adapter import install_aegis, require_auth, require_permission
from aegis.core.config import AegisConfig
from aegis.core.crypto import generate_field_key
from aegis.core.exceptions import SecurityViolation
from aegis.core.policy import Policy

POLICY = (
    Policy()
    .grant("admin", "users:read", "notes:read", "notes:write", "profile:write")
    .grant("user", "notes:read", "notes:write", "profile:write")
)
CONFIG = AegisConfig(
    environment="development", secret_key="k" * 48, field_encryption_key=generate_field_key(),
    rate_limit_per_ip=(50, 60), auth_rate_limit=(50, 60), lockout_threshold=5,
    egress_allow_http=True,
    enabled_modules=("secrets", "headers", "deception", "ratelimit", "authn", "authz",
                     "validation", "encryption", "audit", "anomaly", "errors"),
)
aegis.reset_engine()
ENGINE = aegis.secure(CONFIG, policy=POLICY).engine

USERS = {
    "alice": {"pw": ENGINE.hash_password("password123"), "role": "user"},
    "bob": {"pw": ENGINE.hash_password("bobs-secret"), "role": "user"},
    "admin": {"pw": ENGINE.hash_password("admin123"), "role": "admin"},
}
NOTES = {"alice": ["alice's private note"], "bob": ["bob's private note"]}

app = FastAPI(title="SecureNotes — AEGIS on FastAPI")
install_aegis(app)  # <-- the only security wiring


def _subject(request: Request):
    ctx = request.scope.get("aegis_ctx")
    return ctx.identity.subject if (ctx and ctx.identity.authenticated) else None


class LoginIn(BaseModel):
    username: str
    password: str


class ProfileUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")  # mass-assignment blocked natively
    display_name: str


@app.get("/")
def home():
    return {"service": "SecureNotes [AEGIS on FastAPI]", "ok": True}


@app.post("/login")
def login(body: LoginIn, request: Request):
    user = USERS.get(body.username)
    stored = user["pw"] if user else ""            # enumeration-safe decoy
    roles = (user["role"],) if user else ()
    try:
        token = ENGINE.login(body.username, body.password, stored,
                             ip=request.client.host if request.client else "", roles=roles)
    except SecurityViolation as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.public_message)
    return {"token": token}


@app.get("/notes", dependencies=[Depends(require_permission("notes:read"))])
def notes(request: Request):
    return {"notes": NOTES.get(_subject(request), [])}


@app.get("/admin/users", dependencies=[Depends(require_permission("users:read"))])
def admin_users():
    return {"users": list(USERS.keys())}


@app.post("/profile", dependencies=[Depends(require_auth)])
def profile(body: ProfileUpdate):
    return {"profile": {"display_name": body.display_name}}


@app.get("/fetch")
def fetch(url: str):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise HTTPException(400, "invalid url")
    try:
        ENGINE.check_egress(parsed.geturl())      # SSRF egress guard
    except SecurityViolation as exc:
        raise HTTPException(exc.status_code, exc.public_message)
    try:
        with urllib.request.urlopen(parsed.geturl(), timeout=3) as r:  # nosec B310 - egress-guarded
            return {"fetched": url, "preview": r.read(120).decode("utf-8", "replace")}
    except Exception:
        raise HTTPException(502, "upstream fetch failed")


if __name__ == "__main__":
    import uvicorn
    print("SecureNotes [AEGIS on FastAPI] on http://127.0.0.1:8009")
    uvicorn.run(app, host="127.0.0.1", port=8009)
