"""Adversarial corpus + downstream-failure fail-closed proofs (spec §9.3, §10)."""
from __future__ import annotations

import jwt
import pytest

from aegis.adapters.generic import protect
from aegis.core.exceptions import SecurityViolation
from aegis.core.stores import StoreUnavailable
from tests.helpers import build_engine, make_ctx


class BrokenStore:
    """Simulates a Redis outage: every operation fails."""

    def incr(self, key, ttl): raise StoreUnavailable("redis down")
    def get_int(self, key): raise StoreUnavailable("redis down")
    def set(self, key, value, ttl): raise StoreUnavailable("redis down")
    def get(self, key): raise StoreUnavailable("redis down")
    def ttl(self, key): raise StoreUnavailable("redis down")


# --- fail-closed when the downstream store is unavailable -------------------
def test_rate_limit_store_outage_denies(engine):
    engine.store = BrokenStore()
    deny = engine.handle_request(make_ctx())
    assert deny is not None and deny.status == 503  # deny, not allow-through


def test_lockout_store_outage_denies_login(engine):
    engine.store = BrokenStore()
    stored = engine.hash_password("pw")
    with pytest.raises(SecurityViolation) as exc:
        engine.login("user", "pw", stored)
    assert exc.value.status_code == 503


# --- forged / malformed tokens on a protected route -------------------------
def test_forged_alg_none_bearer_is_rejected(engine):
    forged = jwt.encode({"sub": "attacker", "aud": "aegis", "iss": "aegis", "roles": ["admin"]},
                        key="", algorithm="none")
    ctx = make_ctx(path="/orders", headers={"Authorization": f"Bearer {forged}"})
    ctx.state["require_permission"] = "orders:read"
    deny = engine.handle_request(ctx)
    assert deny is not None and deny.status == 401


def test_garbage_bearer_is_rejected(engine):
    ctx = make_ctx(path="/orders", headers={"Authorization": "Bearer not.a.jwt"})
    deny = engine.handle_request(ctx)
    assert deny is not None and deny.status == 401


def test_expired_bearer_is_rejected(engine):
    expired = engine.issue_token("u", roles=("admin",), ttl=-120)
    ctx = make_ctx(path="/orders", headers={"Authorization": f"Bearer {expired}"})
    deny = engine.handle_request(ctx)
    assert deny is not None and deny.status == 401


# --- mass-assignment / IDOR via unknown fields ------------------------------
def test_schema_rejects_unknown_fields(engine):
    token = engine.issue_token("u", roles=("user",))
    ctx = make_ctx(method="POST", path="/profile",
                   headers={"Authorization": f"Bearer {token}"},
                   body={"name": "ok", "is_admin": True})  # is_admin = privilege grab
    ctx.state["body_schema"] = {"name": str}
    deny = engine.handle_request(ctx)
    assert deny is not None and deny.status == 400


# --- the deny body never leaks internals ------------------------------------
def test_deny_body_is_generic(engine):
    deny = engine.handle_request(make_ctx(method="POST", path="/orders"))  # CSRF deny
    assert set(deny.body.keys()) <= {"error", "correlation_id"}
    assert "Traceback" not in str(deny.body)


# --- generic adapter proves the core is framework-agnostic ------------------
def test_generic_adapter_protect():
    eng = build_engine(rate_limit_per_ip=(1, 60))
    req = {"method": "GET", "path": "/", "remote_addr": "192.0.2.1", "scheme": "https"}
    assert protect(eng, req) is None
    second = protect(eng, req)
    assert second is not None and second.status == 429


# --- alerts go only to configured sinks (no exfiltration) -------------------
def test_alerts_only_to_configured_sinks():
    received = []
    eng = build_engine(alerts=received)
    eng.alert("custom.event", foo="bar")
    assert received and received[-1][0] == "custom.event"
