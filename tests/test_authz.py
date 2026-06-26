"""RBAC deny-by-default (ASVS V4 / OWASP A01)."""
from __future__ import annotations

from aegis.core.policy import Policy
from tests.helpers import make_ctx


def _protected_ctx(engine, roles, permission="orders:read"):
    token = engine.issue_token("subj", roles=roles)
    ctx = make_ctx(method="GET", path="/orders", headers={"Authorization": f"Bearer {token}"})
    ctx.state["require_permission"] = permission
    return ctx


def test_admin_with_wildcard_grant_is_allowed(engine):
    assert engine.handle_request(_protected_ctx(engine, ("admin",))) is None


def test_user_without_grant_is_denied(engine):
    deny = engine.handle_request(_protected_ctx(engine, ("user",)))
    assert deny is not None and deny.status == 403


def test_unauthenticated_on_protected_route_is_401(engine):
    ctx = make_ctx(method="GET", path="/orders")
    ctx.state["require_permission"] = "orders:read"
    deny = engine.handle_request(ctx)
    assert deny is not None and deny.status == 401


def test_unknown_role_denied_by_default():
    p = Policy()  # empty policy -> everything denied
    assert p.allows(("whatever",), "orders:read") is False


def test_namespace_wildcard_grant():
    p = Policy().grant("admin", "orders:*")
    assert p.allows(("admin",), "orders:read") is True
    assert p.allows(("admin",), "orders:delete") is True
    assert p.allows(("admin",), "users:read") is False


def test_role_inheritance():
    p = Policy().grant("base", "profile:read").inherit("member", "base").grant("member", "orders:read")
    assert p.allows(("member",), "profile:read") is True
    assert p.allows(("member",), "orders:read") is True


def test_require_all_listed_permissions(engine):
    # admin has orders:* and users:read -> both satisfied
    ctx = _protected_ctx(engine, ("admin",), permission=("orders:read", "users:read"))
    assert engine.handle_request(ctx) is None
    # auditor has orders:read but NOT users:read -> denied
    ctx2 = _protected_ctx(engine, ("auditor",), permission=("orders:read", "users:read"))
    deny = engine.handle_request(ctx2)
    assert deny is not None and deny.status == 403
