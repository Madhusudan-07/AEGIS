"""Fail-closed proof obligations (spec §10): AEGIS REFUSES TO BOOT when unsafe."""
from __future__ import annotations

import pytest

from aegis.core.config import AegisConfig
from aegis.core.crypto import generate_field_key
from aegis.core.engine import Engine
from aegis.core.exceptions import BootSelfCheckError

STRONG = "s" * 48


def boot(**cfg_kwargs):
    return Engine(AegisConfig(**cfg_kwargs)).boot()


def test_missing_secret_in_production_refuses_to_boot():
    with pytest.raises(BootSelfCheckError):
        boot(environment="production", secret_key="")


def test_weak_secret_in_production_refuses_to_boot():
    with pytest.raises(BootSelfCheckError):
        boot(environment="production", secret_key="changeme")


def test_short_secret_in_production_refuses_to_boot():
    with pytest.raises(BootSelfCheckError):
        boot(environment="production", secret_key="short")


def test_wildcard_cors_in_production_refuses_to_boot():
    with pytest.raises(BootSelfCheckError):
        boot(environment="production", secret_key=STRONG, cors_allowed_origins=("*",))


def test_tls_not_expected_in_production_refuses_to_boot():
    with pytest.raises(BootSelfCheckError):
        boot(environment="production", secret_key=STRONG, require_tls=False)


def test_non_https_cors_origin_in_production_refuses_to_boot():
    with pytest.raises(BootSelfCheckError):
        boot(environment="production", secret_key=STRONG,
             cors_allowed_origins=("http://app.example.com",))


def test_invalid_encryption_key_refuses_to_boot():
    with pytest.raises(BootSelfCheckError):
        boot(environment="test", secret_key=STRONG, field_encryption_key="not-a-32-byte-key")


def test_safe_production_config_boots():
    eng = boot(
        environment="production", secret_key=STRONG, require_tls=True,
        cors_allowed_origins=("https://app.example.com",),
        field_encryption_key=generate_field_key(),
    )
    assert eng.booted is True


def test_handle_request_before_boot_is_denied():
    eng = Engine(AegisConfig(environment="test", secret_key=STRONG))
    with pytest.raises(BootSelfCheckError):
        eng.handle_request(object())  # never booted
