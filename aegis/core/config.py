"""Typed, validated, secure-by-default configuration.

``AegisConfig`` is the single source of truth for every module. It can be built
explicitly, or auto-detected from the environment with :meth:`AegisConfig.from_env`.
``validate()`` performs *structural* validation (fail-closed on bad types / missing
required fields); environment-safety gates (wildcard CORS, TLS, weak secrets) are
enforced by the boot self-check in :mod:`aegis.core.engine` so the failure surfaces
as a clear ``BootSelfCheckError``.
"""
from __future__ import annotations

import os
import secrets as _secrets
import warnings
from dataclasses import dataclass, field, fields
from typing import Mapping

from ..config import defaults as D
from .exceptions import ConfigError

ENVIRONMENTS = ("production", "staging", "development", "test")


def _as_bool(value: str | bool) -> bool:
    if isinstance(value, bool):
        return value
    return value.strip().lower() in ("1", "true", "yes", "on")


def _as_tuple(value: str | tuple) -> tuple[str, ...]:
    if isinstance(value, (tuple, list)):
        return tuple(str(v).strip() for v in value if str(v).strip())
    return tuple(p.strip() for p in value.split(",") if p.strip())


@dataclass
class AegisConfig:
    # --- environment ---------------------------------------------------------
    environment: str = "production"  # fail-closed: assume prod unless told otherwise

    # --- secrets (loaded from env / secret manager ONLY) ---------------------
    secret_key: str = ""             # HMAC for JWT(HS*)/CSRF; >=32 chars in prod
    field_encryption_key: str = ""   # urlsafe-b64 of 32 bytes for AES-256-GCM

    # --- transport / CORS ----------------------------------------------------
    require_tls: bool = True                         # prod gate
    cors_allowed_origins: tuple[str, ...] = ()       # NO "*" in prod (boot-refused)
    trusted_proxies: tuple[str, ...] = ()            # only these may set X-Forwarded-For
    csp: str = D.DEFAULT_CSP
    hsts_max_age: int = D.DEFAULT_HSTS_MAX_AGE

    # --- datastores ----------------------------------------------------------
    redis_url: str = ""              # empty -> in-memory stores (dev only)
    # When True (production default) a configured-but-unreachable store DENIES
    # rather than allowing requests through (fail-closed; ASVS V1.5).
    fail_closed_on_store_error: bool = True

    # --- tokens / authn ------------------------------------------------------
    jwt_algorithm: str = D.DEFAULT_JWT_ALGORITHM
    jwt_issuer: str = "aegis"
    jwt_audience: str = "aegis"
    access_ttl: int = D.DEFAULT_ACCESS_TTL
    refresh_ttl: int = D.DEFAULT_REFRESH_TTL
    jwt_leeway: int = D.DEFAULT_JWT_LEEWAY
    # For asymmetric algs (RS*/ES*/EdDSA) the public key used to VERIFY:
    jwt_public_key: str = ""

    # --- rate limit ----------------------------------------------------------
    rate_limit_per_ip: tuple[int, int] = D.DEFAULT_RATE_LIMIT_PER_IP
    rate_limit_per_identity: tuple[int, int] = D.DEFAULT_RATE_LIMIT_PER_IDENTITY
    auth_rate_limit: tuple[int, int] = D.DEFAULT_AUTH_RATE_LIMIT
    lockout_threshold: int = D.DEFAULT_LOCKOUT_THRESHOLD
    lockout_base_seconds: int = D.DEFAULT_LOCKOUT_BASE_SECONDS
    auth_path_prefixes: tuple[str, ...] = ("/auth", "/login", "/api/auth")

    # --- session / cookies ---------------------------------------------------
    cookie_secure: bool = True
    cookie_samesite: str = "Lax"
    session_ttl: int = D.DEFAULT_SESSION_TTL
    csrf_safe_methods: tuple[str, ...] = ("GET", "HEAD", "OPTIONS", "TRACE")

    # --- anomaly -------------------------------------------------------------
    anomaly_authfail_threshold: int = D.DEFAULT_ANOMALY_AUTHFAIL_THRESHOLD
    anomaly_window: int = D.DEFAULT_ANOMALY_WINDOW

    # --- module toggles (each independently on/off; Requirement B) -----------
    enabled_modules: tuple[str, ...] = (
        "secrets", "headers", "ratelimit", "authn", "authz",
        "validation", "session", "encryption", "audit", "anomaly", "errors",
    )

    # internal flag: set when we had to invent an ephemeral dev secret
    _ephemeral_secret: bool = field(default=False, repr=False)

    # ---------------------------------------------------------------------
    @property
    def is_production(self) -> bool:
        return self.environment in ("production", "staging")

    def module_enabled(self, name: str) -> bool:
        return name in self.enabled_modules

    # ---------------------------------------------------------------------
    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None, prefix: str = "AEGIS_") -> "AegisConfig":
        """Auto-detect configuration from environment variables (Requirement A).

        Recognized vars (all optional except in production): ``AEGIS_ENV``,
        ``AEGIS_SECRET_KEY``, ``AEGIS_FIELD_ENCRYPTION_KEY``, ``AEGIS_REQUIRE_TLS``,
        ``AEGIS_CORS_ORIGINS``, ``AEGIS_TRUSTED_PROXIES``, ``AEGIS_REDIS_URL``,
        ``AEGIS_JWT_ALGORITHM``, ``AEGIS_DISABLED_MODULES`` …
        """
        env = dict(os.environ if environ is None else environ)

        def g(name: str, default: str = "") -> str:
            return env.get(prefix + name, default)

        environment = g("ENV", env.get("DJANGO_ENV", "production")).strip().lower()
        if environment not in ENVIRONMENTS:
            environment = "production"

        cfg = cls(
            environment=environment,
            secret_key=g("SECRET_KEY"),
            field_encryption_key=g("FIELD_ENCRYPTION_KEY"),
            redis_url=g("REDIS_URL"),
            jwt_public_key=g("JWT_PUBLIC_KEY"),
        )
        if g("REQUIRE_TLS"):
            cfg.require_tls = _as_bool(g("REQUIRE_TLS"))
        if g("CORS_ORIGINS"):
            cfg.cors_allowed_origins = _as_tuple(g("CORS_ORIGINS"))
        if g("TRUSTED_PROXIES"):
            cfg.trusted_proxies = _as_tuple(g("TRUSTED_PROXIES"))
        if g("JWT_ALGORITHM"):
            cfg.jwt_algorithm = g("JWT_ALGORITHM")
        if g("CSP"):
            cfg.csp = g("CSP")
        if g("DISABLED_MODULES"):
            disabled = set(_as_tuple(g("DISABLED_MODULES")))
            cfg.enabled_modules = tuple(m for m in cfg.enabled_modules if m not in disabled)

        cfg._fill_ephemeral_dev_secret()
        return cfg

    def _fill_ephemeral_dev_secret(self) -> None:
        """In non-prod only, invent a strong ephemeral secret so dev 'just works'.

        Production NEVER reaches here with an empty secret — the boot self-check
        refuses to start first.
        """
        if not self.secret_key and not self.is_production:
            self.secret_key = _secrets.token_urlsafe(48)
            self._ephemeral_secret = True
            warnings.warn(
                "AEGIS: no AEGIS_SECRET_KEY set; generated an EPHEMERAL dev secret. "
                "Tokens/sessions will not survive a restart. Never do this in production.",
                stacklevel=2,
            )

    # ---------------------------------------------------------------------
    def validate(self) -> None:
        """Structural validation. Raises :class:`ConfigError` on malformed config."""
        if self.environment not in ENVIRONMENTS:
            raise ConfigError(f"environment must be one of {ENVIRONMENTS}")
        for f in (
            "access_ttl", "refresh_ttl", "session_ttl", "lockout_threshold",
            "anomaly_authfail_threshold", "hsts_max_age",
        ):
            if not isinstance(getattr(self, f), int) or getattr(self, f) <= 0:
                raise ConfigError(f"{f} must be a positive integer")
        for pair_name in ("rate_limit_per_ip", "rate_limit_per_identity", "auth_rate_limit"):
            pair = getattr(self, pair_name)
            if not (isinstance(pair, tuple) and len(pair) == 2 and all(isinstance(x, int) and x > 0 for x in pair)):
                raise ConfigError(f"{pair_name} must be a (limit, window_seconds) tuple of positive ints")
        if self.cookie_samesite not in ("Strict", "Lax", "None"):
            raise ConfigError("cookie_samesite must be Strict|Lax|None")
        if not isinstance(self.enabled_modules, tuple):
            raise ConfigError("enabled_modules must be a tuple")

    def redacted(self) -> dict:
        """A repr safe to log: secrets/keys are masked (no-exfiltration, ASVS V7)."""
        out = {}
        for f in fields(self):
            if f.name.startswith("_"):
                continue
            val = getattr(self, f.name)
            if any(s in f.name for s in ("secret", "key", "password", "token")):
                val = "***REDACTED***" if val else "(unset)"
            out[f.name] = val
        return out
