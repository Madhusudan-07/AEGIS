"""Property-based fuzzing of AEGIS trust-boundary surfaces (Subsystem A).

These assert *invariants* over a large space of inputs, not single examples:
the cipher always round-trips, tampered ciphertext always fails closed, and the
request pipeline NEVER crashes on hostile input — it returns or denies, never raises.
"""
from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from aegis.core.crypto import FieldCipher, TokenService, generate_field_key
from aegis.core.exceptions import CryptoError
from tests.helpers import build_engine, make_ctx

# One engine for the whole module; rate limit raised so fuzzing doesn't self-throttle.
_ENGINE = build_engine(rate_limit_per_ip=(10**9, 60), auth_rate_limit=(10**9, 60))
_CIPHER = FieldCipher(generate_field_key())
_TOKENS = TokenService("k" * 48, algorithm="HS256", issuer="aegis", audience="aegis")


@given(st.binary(max_size=4096))
@settings(max_examples=150, deadline=None)
def test_field_cipher_round_trips_any_bytes(data):
    assert _CIPHER.decrypt(_CIPHER.encrypt(data)) == data


@given(st.text(max_size=128))
@settings(max_examples=100, deadline=None)
def test_unrecognized_ciphertext_fails_closed(blob):
    # Anything not produced by AEGIS must never decrypt to plaintext.
    try:
        _CIPHER.decrypt(blob)
    except CryptoError:
        return
    raise AssertionError("non-AEGIS ciphertext unexpectedly decrypted")


@given(st.text(min_size=1, max_size=64))
@settings(max_examples=100, deadline=None)
def test_token_subject_survives_round_trip(subject):
    payload = _TOKENS.verify(_TOKENS.issue(subject, ttl=60), expected_type="access")
    assert payload["sub"] == subject


@given(
    method=st.sampled_from(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "\x00"]),
    path=st.text(max_size=128),
    headers=st.dictionaries(st.text(max_size=24), st.text(max_size=128), max_size=8),
)
@settings(max_examples=200, deadline=None)
def test_pipeline_never_crashes_on_hostile_input(method, path, headers):
    # Fail-closed contract: the engine either allows (None) or denies (ResponseContext).
    # It must NEVER raise an unhandled exception to the host app.
    ctx = make_ctx(method=method, path=path, headers=headers)
    result = _ENGINE.handle_request(ctx)
    assert result is None or hasattr(result, "status")
