"""Request-pipeline behavior: headers, CORS, validation, CSRF, rate limiting."""
from __future__ import annotations

from aegis.core.context import ResponseContext
from tests.helpers import build_engine, make_ctx


# --- happy path -------------------------------------------------------------
def test_plain_get_is_allowed(engine):
    assert engine.handle_request(make_ctx()) is None


# --- security headers + CORS ------------------------------------------------
def test_security_headers_applied_on_response(engine):
    ctx = make_ctx(scheme="https")
    rc = ResponseContext(status=200)
    engine.handle_response(ctx, rc)
    assert rc.headers["X-Content-Type-Options"] == "nosniff"
    assert rc.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in rc.headers
    assert "Strict-Transport-Security" in rc.headers  # only over https


def test_cors_echoes_only_allowed_origin(engine):
    ctx = make_ctx(headers={"Origin": "https://app.example.com"})
    rc = ResponseContext(status=200)
    engine.handle_response(ctx, rc)
    assert rc.headers["Access-Control-Allow-Origin"] == "https://app.example.com"
    assert "*" not in rc.headers.values()


def test_cors_blocks_unlisted_origin(engine):
    ctx = make_ctx(headers={"Origin": "https://evil.example.com"})
    rc = ResponseContext(status=200)
    engine.handle_response(ctx, rc)
    assert "Access-Control-Allow-Origin" not in rc.headers


# --- input validation -------------------------------------------------------
def test_null_byte_in_path_is_rejected(engine):
    deny = engine.handle_request(make_ctx(path="/api/\x00/etc/passwd"))
    assert deny is not None and deny.status == 400


# --- CSRF -------------------------------------------------------------------
def test_post_without_csrf_is_denied(engine):
    deny = engine.handle_request(make_ctx(method="POST", path="/orders"))
    assert deny is not None and deny.status == 403


def test_post_with_valid_double_submit_passes(engine):
    token = engine.module("session").issue_csrf_token()
    deny = engine.handle_request(make_ctx(
        method="POST", path="/orders",
        headers={"X-CSRF-Token": token},
        cookies={"aegis_csrf": token},
    ))
    assert deny is None


def test_post_with_mismatched_csrf_is_denied(engine):
    good = engine.module("session").issue_csrf_token()
    other = engine.module("session").issue_csrf_token()
    deny = engine.handle_request(make_ctx(
        method="POST", path="/orders",
        headers={"X-CSRF-Token": good},
        cookies={"aegis_csrf": other},
    ))
    assert deny is not None and deny.status == 403


def test_bearer_post_is_csrf_exempt(engine):
    token = engine.issue_token("user-1", roles=("user",))
    deny = engine.handle_request(make_ctx(
        method="POST", path="/orders",
        headers={"Authorization": f"Bearer {token}"},
    ))
    assert deny is None  # token auth carries no ambient credential


# --- rate limiting ----------------------------------------------------------
def test_rate_limit_blocks_after_threshold():
    eng = build_engine(rate_limit_per_ip=(3, 60))
    ip = "198.51.100.9"
    results = [eng.handle_request(make_ctx(remote_addr=ip)) for _ in range(4)]
    assert results[0] is None and results[1] is None and results[2] is None
    assert results[3] is not None and results[3].status == 429
    assert "Retry-After" in results[3].headers


def test_auth_path_has_tighter_limit():
    eng = build_engine(auth_rate_limit=(2, 60))
    ip = "198.51.100.10"
    r = [eng.handle_request(make_ctx(path="/auth/login", remote_addr=ip)) for _ in range(3)]
    assert r[2] is not None and r[2].status == 429


# --- denial responses are still hardened ------------------------------------
def test_denied_response_still_carries_security_headers(engine):
    deny = engine.handle_request(make_ctx(method="POST", path="/orders"))  # CSRF deny
    assert deny.headers.get("X-Content-Type-Options") == "nosniff"
