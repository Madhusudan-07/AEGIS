"""AEGIS core — framework-agnostic. Import nothing framework-specific from here."""
from .config import AegisConfig
from .context import Identity, RequestContext, ResponseContext
from .engine import Engine
from .exceptions import (
    AegisError,
    AuthenticationError,
    AuthorizationError,
    BootSelfCheckError,
    ConfigError,
    CryptoError,
    CsrfError,
    RateLimitExceeded,
    SecretError,
    SecurityViolation,
    ValidationFailed,
)
from .policy import Policy

__all__ = [
    "AegisConfig", "Engine", "Policy",
    "Identity", "RequestContext", "ResponseContext",
    "AegisError", "BootSelfCheckError", "ConfigError", "SecurityViolation",
    "AuthenticationError", "AuthorizationError", "ValidationFailed",
    "RateLimitExceeded", "CsrfError", "SecretError", "CryptoError",
]
