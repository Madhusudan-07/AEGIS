"""AEGIS exception hierarchy.

Principle: **fail closed**. Every security-relevant failure raises a subclass of
``SecurityViolation`` (deny the request) or ``BootSelfCheckError`` (refuse to boot).
Client-facing text is always generic; detail goes to the internal audit log only
(see ``aegis.core.modules.errors``).
"""
from __future__ import annotations


class AegisError(Exception):
    """Base class for everything AEGIS raises."""


class ConfigError(AegisError):
    """Configuration is structurally invalid (wrong types, missing required field)."""


class BootSelfCheckError(AegisError):
    """The boot-time self-check found an UNSAFE environment. Refuse to start.

    Raised for: missing/empty required secret, wildcard CORS in production,
    TLS not expected in production, encryption enabled without a key, etc.
    """


class SecurityViolation(AegisError):
    """Base for any per-request denial. Maps to a generic 4xx for the client.

    Attributes
    ----------
    status_code: int   HTTP status to return (default 403).
    public_message: str  Safe, generic message for the client (never leaks internals).
    """

    status_code = 403
    public_message = "Request denied."

    def __init__(self, detail: str = "", *, public_message: str | None = None):
        # ``detail`` is internal-only (audited, never returned to the client).
        super().__init__(detail or self.__class__.__name__)
        if public_message is not None:
            self.public_message = public_message


class AuthenticationError(SecurityViolation):
    status_code = 401
    public_message = "Authentication required."


class AuthorizationError(SecurityViolation):
    status_code = 403
    public_message = "You do not have permission to perform this action."


class ValidationFailed(SecurityViolation):
    status_code = 400
    public_message = "Invalid request."


class RateLimitExceeded(SecurityViolation):
    status_code = 429
    public_message = "Too many requests. Please slow down."

    def __init__(self, detail: str = "", *, retry_after: int | None = None):
        super().__init__(detail)
        self.retry_after = retry_after


class CsrfError(SecurityViolation):
    status_code = 403
    public_message = "Invalid or missing CSRF token."


class EgressBlocked(SecurityViolation):
    """An outbound (server-side) request targeted a forbidden destination (SSRF)."""

    status_code = 400
    public_message = "The requested URL is not allowed."


class SecretError(BootSelfCheckError):
    """A required secret/key is missing, empty, or hardcoded."""


class CryptoError(AegisError):
    """A cryptographic operation failed (bad key, tampered ciphertext, etc.)."""
