"""Crypto wrappers: argon2id, JWT (alg pinned / none rejected), AES-256-GCM, CSPRNG."""
from __future__ import annotations

import time

import jwt
import pytest

from aegis.core.crypto import (
    FieldCipher,
    TokenService,
    generate_field_key,
    hash_password,
    password_needs_rehash,
    random_token,
    verify_password,
)
from aegis.core.exceptions import AuthenticationError, CryptoError


# --- passwords --------------------------------------------------------------
def test_argon2id_hash_and_verify():
    h = hash_password("correct horse battery staple")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "correct horse battery staple") is True
    assert verify_password(h, "wrong") is False


def test_verify_password_never_raises_on_garbage():
    assert verify_password("not-a-hash", "x") is False
    assert password_needs_rehash("not-a-hash") is True


# --- random -----------------------------------------------------------------
def test_random_tokens_are_unique_and_long():
    tokens = {random_token() for _ in range(500)}
    assert len(tokens) == 500
    assert all(len(t) >= 32 for t in tokens)


# --- JWT --------------------------------------------------------------------
def ts():
    return TokenService("k" * 48, algorithm="HS256", issuer="aegis", audience="aegis")


def test_jwt_round_trip():
    svc = ts()
    token = svc.issue("user-1", ttl=60, roles=("admin",))
    payload = svc.verify(token, expected_type="access")
    assert payload["sub"] == "user-1"
    assert payload["roles"] == ["admin"]


def test_jwt_alg_none_is_rejected_at_construction():
    with pytest.raises(CryptoError):
        TokenService("k" * 48, algorithm="none")


def test_forged_alg_none_token_is_rejected():
    forged = jwt.encode({"sub": "attacker", "aud": "aegis", "iss": "aegis"}, key="", algorithm="none")
    with pytest.raises(AuthenticationError):
        ts().verify(forged)


def test_expired_token_is_rejected():
    token = ts().issue("user-1", ttl=-120)  # expired well beyond the 10s leeway
    with pytest.raises(AuthenticationError):
        ts().verify(token)


def test_tampered_token_is_rejected():
    token = ts().issue("user-1", ttl=60)
    head, payload, sig = token.split(".")
    tampered = ".".join([head, payload[:-2] + ("AA" if payload[-2:] != "AA" else "BB"), sig])
    with pytest.raises(AuthenticationError):
        ts().verify(tampered)


def test_wrong_audience_is_rejected():
    token = ts().issue("user-1", ttl=60)
    other = TokenService("k" * 48, algorithm="HS256", issuer="aegis", audience="someone-else")
    with pytest.raises(AuthenticationError):
        other.verify(token)


def test_token_type_mismatch_rejected():
    svc = ts()
    refresh = svc.issue("user-1", ttl=60, token_type="refresh")
    with pytest.raises(AuthenticationError):
        svc.verify(refresh, expected_type="access")


# --- field encryption (AES-256-GCM) ----------------------------------------
def test_field_encrypt_decrypt_round_trip():
    cipher = FieldCipher(generate_field_key())
    ct = cipher.encrypt("ssn:123-45-6789")
    assert ct.startswith("aegis1:")
    assert cipher.decrypt(ct) == b"ssn:123-45-6789"


def test_tampered_ciphertext_fails_closed():
    cipher = FieldCipher(generate_field_key())
    ct = cipher.encrypt("secret pii")
    tampered = ct[:-3] + ("AAA" if ct[-3:] != "AAA" else "BBB")
    with pytest.raises(CryptoError):
        cipher.decrypt(tampered)


def test_wrong_key_cannot_decrypt():
    ct = FieldCipher(generate_field_key()).encrypt("data")
    with pytest.raises(CryptoError):
        FieldCipher(generate_field_key()).decrypt(ct)


def test_aad_must_match():
    cipher = FieldCipher(generate_field_key())
    ct = cipher.encrypt("data", aad=b"user:1")
    assert cipher.decrypt(ct, aad=b"user:1") == b"data"
    with pytest.raises(CryptoError):
        cipher.decrypt(ct, aad=b"user:2")
