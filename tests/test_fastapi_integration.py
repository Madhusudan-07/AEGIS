"""Proof of Requirement B: the SAME AEGIS core protects FastAPI via one adapter.

No aegis/core/ changes — just aegis/adapters/fastapi_adapter.py. These assertions mirror
the Django integration test, on a different framework, through the same engine + modules.
"""
from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")

import jwt  # noqa: E402
from fastapi import Depends, FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from pydantic import BaseModel, ConfigDict  # noqa: E402

import aegis  # noqa: E402
from aegis.adapters.fastapi_adapter import install_aegis, require_auth, require_permission  # noqa: E402
from aegis.core.config import AegisConfig  # noqa: E402
from aegis.core.crypto import generate_field_key  # noqa: E402
from aegis.core.policy import Policy  # noqa: E402

app = FastAPI()
install_aegis(app)  # <-- the only security wiring


class ProfileUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")  # mass-assignment blocked by Pydantic natively
    display_name: str


@app.get("/")
def home():
    return {"ok": True}


@app.get("/admin/users", dependencies=[Depends(require_permission("users:read"))])
def admin_users():
    return {"users": ["alice", "bob"]}


@app.post("/profile", dependencies=[Depends(require_auth)])
def profile(body: ProfileUpdate):
    return {"display_name": body.display_name}


@pytest.fixture(autouse=True)
def _engine():
    aegis.reset_engine()
    aegis.secure(
        AegisConfig(
            environment="development", secret_key="k" * 48,
            field_encryption_key=generate_field_key(),
            enabled_modules=("secrets", "headers", "ratelimit", "authn", "authz",
                             "validation", "encryption", "audit", "anomaly", "errors"),
        ),
        policy=Policy().grant("admin", "users:read"),
    )
    yield
    aegis.reset_engine()


@pytest.fixture
def client():
    return TestClient(app)


def test_same_core_adds_security_headers(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"


def test_forged_alg_none_token_rejected(client):
    forged = jwt.encode({"sub": "ghost", "aud": "aegis", "iss": "aegis", "roles": ["admin"]},
                        key="", algorithm="none")
    r = client.get("/admin/users", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401


def test_broken_access_control_denied(client):
    tok = aegis.get_engine().issue_token("u", roles=("user",))  # valid low-priv token
    r = client.get("/admin/users", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403


def test_admin_allowed(client):
    tok = aegis.get_engine().issue_token("u", roles=("admin",))
    r = client.get("/admin/users", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200 and r.json()["users"] == ["alice", "bob"]


def test_anonymous_on_protected_is_401(client):
    assert client.get("/admin/users").status_code == 401


def test_mass_assignment_blocked_natively(client):
    tok = aegis.get_engine().issue_token("u", roles=("admin",))
    r = client.post("/profile", headers={"Authorization": f"Bearer {tok}"},
                    json={"display_name": "x", "role": "admin"})
    assert r.status_code == 422  # Pydantic extra="forbid" rejects the smuggled field
