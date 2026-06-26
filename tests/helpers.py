"""Importable test helpers (kept out of conftest so test modules can import them)."""
from __future__ import annotations

from aegis.adapters.generic import GenericAdapter
from aegis.core.config import AegisConfig
from aegis.core.crypto import generate_field_key
from aegis.core.engine import Engine
from aegis.core.policy import Policy

STRONG = "k" * 48


def make_config(**overrides) -> AegisConfig:
    base = dict(
        environment="test",
        secret_key=STRONG,
        field_encryption_key=generate_field_key(),
        cors_allowed_origins=("https://app.example.com",),
    )
    base.update(overrides)
    return AegisConfig(**base)


def make_policy() -> Policy:
    return (
        Policy()
        .grant("admin", "orders:*", "users:read")
        .grant("auditor", "orders:read")
        .grant("user", "profile:read")
    )


def build_engine(*, alerts=None, **cfg_overrides) -> Engine:
    sinks = [lambda kind, fields: alerts.append((kind, fields))] if alerts is not None else None
    eng = Engine(make_config(**cfg_overrides), policy=make_policy(), alert_sinks=sinks)
    eng.boot()
    return eng


def make_ctx(*, method="GET", path="/", headers=None, cookies=None,
             body=None, remote_addr="203.0.113.7", scheme="https", query=None):
    return GenericAdapter().build_context({
        "method": method,
        "path": path,
        "headers": headers or {},
        "cookies": cookies or {},
        "query": query or {},
        "body": body,
        "remote_addr": remote_addr,
        "scheme": scheme,
    })
