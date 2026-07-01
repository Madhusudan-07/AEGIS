"""AEGIS — plug-and-play, secure-by-default, fail-closed security layer.

The ONE step (Requirement A)::

    from aegis import secure
    secure()            # auto-detects env, boots all modules, fails closed if unsafe

In Django, the one step is adding the middleware (which boots AEGIS at startup):

    MIDDLEWARE = ["aegis.adapters.django_adapter.AegisMiddleware", ...]

Everything is secure with zero config; every default is overridable.
"""
from __future__ import annotations

from .core import (
    AegisConfig,
    AegisError,
    AuthenticationError,
    AuthorizationError,
    BootSelfCheckError,
    CsrfError,
    Engine,
    Identity,
    Policy,
    RateLimitExceeded,
    RequestContext,
    ResponseContext,
    SecurityViolation,
    ValidationFailed,
)

__version__ = "0.1.0"

# Module-global engine: booted once, reused by adapters.
_ENGINE: Engine | None = None


class SecureHandle:
    """Thin façade returned by :func:`secure` — exposes the safe public API."""

    def __init__(self, engine: Engine):
        self.engine = engine
        self.policy = engine.policy

    # auth
    def login(self, identifier, password, stored_hash, *, ip="", roles=()):
        return self.engine.login(identifier, password, stored_hash, ip=ip, roles=roles)

    def issue_token(self, subject, **kw):
        return self.engine.issue_token(subject, **kw)

    def hash_password(self, password):
        return self.engine.hash_password(password)

    def verify_password(self, stored_hash, password):
        return self.engine.verify_password(stored_hash, password)

    # field encryption
    def encrypt_field(self, plaintext, *, aad=b""):
        return self.engine.encrypt_field(plaintext, aad=aad)

    def decrypt_field(self, token, *, aad=b""):
        return self.engine.decrypt_field(token, aad=aad)

    # SSRF egress guard — validate an outbound URL before fetching it
    def check_egress(self, url):
        return self.engine.check_egress(url)

    @property
    def audit(self):
        return self.engine.audit


def secure(config: AegisConfig | None = None, *, policy: Policy | None = None,
           alert_sinks=None, audit_sink=None) -> SecureHandle:
    """Build, boot (fail-closed self-check), and install the global AEGIS engine.

    Zero-config: ``secure()`` auto-detects configuration from the environment. Pass a
    :class:`AegisConfig` and/or :class:`Policy` to override any default safely.
    """
    global _ENGINE
    cfg = config or AegisConfig.from_env()
    engine = Engine(cfg, policy=policy, alert_sinks=alert_sinks, audit_sink=audit_sink)
    engine.boot()  # raises BootSelfCheckError on an unsafe environment
    _ENGINE = engine
    return SecureHandle(engine)


def get_engine(*, autoboot: bool = True) -> Engine:
    """Return the installed engine. If none and ``autoboot``, boot one from the env."""
    global _ENGINE
    if _ENGINE is None:
        if not autoboot:
            raise BootSelfCheckError("AEGIS not initialized; call secure() first")
        secure()
    return _ENGINE  # type: ignore[return-value]


def reset_engine() -> None:
    """Test helper: drop the global engine."""
    global _ENGINE
    _ENGINE = None


__all__ = [
    "secure", "get_engine", "reset_engine", "SecureHandle", "__version__",
    "AegisConfig", "Engine", "Policy",
    "Identity", "RequestContext", "ResponseContext",
    "AegisError", "BootSelfCheckError", "SecurityViolation",
    "AuthenticationError", "AuthorizationError", "ValidationFailed",
    "RateLimitExceeded", "CsrfError",
]
