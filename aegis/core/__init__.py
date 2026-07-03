"""AEGIS core — framework-agnostic. Import nothing framework-specific from here."""
from .config import AegisConfig
from .context import Identity, RequestContext, ResponseContext
from .engine import Engine
from .events import EventStream, RedisEventStream, build_event_stream
from .exceptions import (
    AegisError,
    AuthenticationError,
    AuthorizationError,
    BootSelfCheckError,
    ConfigError,
    CryptoError,
    CsrfError,
    EgressBlocked,
    RateLimitExceeded,
    SecretError,
    SecurityViolation,
    ValidationFailed,
)
from .policy import Policy
from .sinks import FileAuditSink, PostgresAuditSink, fan_out

__all__ = [
    "AegisConfig", "Engine", "Policy", "EventStream",
    "RedisEventStream", "build_event_stream",
    "FileAuditSink", "PostgresAuditSink", "fan_out",
    "Identity", "RequestContext", "ResponseContext",
    "AegisError", "BootSelfCheckError", "ConfigError", "SecurityViolation",
    "AuthenticationError", "AuthorizationError", "ValidationFailed",
    "RateLimitExceeded", "CsrfError", "SecretError", "CryptoError", "EgressBlocked",
]
