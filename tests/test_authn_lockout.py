"""Login: argon2 verification, lockout w/ backoff, enumeration-safe responses."""
from __future__ import annotations

import pytest

from aegis.core.exceptions import AuthenticationError
from tests.helpers import build_engine


def test_successful_login_issues_token(engine):
    stored = engine.hash_password("hunter2")
    token = engine.login("alice", "hunter2", stored, roles=("user",))
    payload = engine.tokens.verify(token, expected_type="access")
    assert payload["sub"] == "alice"


def test_wrong_password_raises_generic_error(engine):
    stored = engine.hash_password("hunter2")
    with pytest.raises(AuthenticationError) as exc:
        engine.login("alice", "wrong", stored)
    # Same message whether or not the user exists -> no account enumeration.
    assert exc.value.public_message == "Invalid email or password."


def test_unknown_user_same_message_as_wrong_password(engine):
    with pytest.raises(AuthenticationError) as exc:
        engine.login("ghost", "whatever", stored_hash="")  # app passes decoy/empty
    assert exc.value.public_message == "Invalid email or password."


def test_lockout_after_threshold_failures():
    eng = build_engine(lockout_threshold=3, lockout_base_seconds=30)
    stored = eng.hash_password("hunter2")
    for _ in range(3):
        with pytest.raises(AuthenticationError):
            eng.login("bob", "wrong", stored, ip="203.0.113.50")
    # Now locked: even the CORRECT password is refused with the lockout message.
    with pytest.raises(AuthenticationError) as exc:
        eng.login("bob", "hunter2", stored, ip="203.0.113.50")
    assert "Too many attempts" in exc.value.public_message


def test_anomaly_alert_fires_on_failure_spike():
    alerts = []
    eng = build_engine(alerts=alerts, anomaly_authfail_threshold=3, lockout_threshold=99)
    stored = eng.hash_password("pw")
    for _ in range(3):
        with pytest.raises(AuthenticationError):
            eng.login("carol", "nope", stored, ip="203.0.113.60")
    kinds = [a[0] for a in alerts]
    assert "anomaly.auth_failure_spike" in kinds
