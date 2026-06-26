"""Redaction — no secret, key, token, or obvious PII may reach a log or client.

Used by Audit (every record), SafeErrors (every client/log message), and Secrets
(config dump). Implements spec Principle 7 (no exfiltration) and ASVS V7.1.
"""
from __future__ import annotations

import re

REDACTED = "***REDACTED***"

# Field names whose values are always masked, regardless of content.
_SENSITIVE_KEYS = re.compile(
    r"(secret|token|password|passwd|authorization|api[-_]?key|private[-_]?key|"
    r"cookie|set-cookie|ssn|card|cvv|pin)",
    re.IGNORECASE,
)

# Value patterns redacted wherever they appear in free text.
_VALUE_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}"),  # JWT
    re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),                                    # email
    re.compile(r"\b(?:\d[ -]?){13,19}\b"),                                          # card-like PAN
    re.compile(r"\baegis1:[A-Za-z0-9_-]+"),                                         # AEGIS ciphertext
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]+"),                                    # bearer token
]


def redact_value(value):
    if isinstance(value, str):
        out = value
        for pat in _VALUE_PATTERNS:
            out = pat.sub(REDACTED, out)
        return out
    return value


def redact(obj):
    """Recursively redact a dict/list/str by key name and by value pattern."""
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            if isinstance(k, str) and _SENSITIVE_KEYS.search(k):
                result[k] = REDACTED if v not in (None, "", "(unset)") else v
            else:
                result[k] = redact(v)
        return result
    if isinstance(obj, (list, tuple)):
        return type(obj)(redact(v) for v in obj)
    return redact_value(obj)
