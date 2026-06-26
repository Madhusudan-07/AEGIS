"""Module 6 — Encryption (field-level helper for sensitive data at rest).

ASVS V6 · OWASP A02. The AES-256-GCM cipher itself lives in :mod:`aegis.core.crypto`
(wrapping ``cryptography``); this module validates the key at boot and exposes the
engine's ``encrypt_field`` / ``decrypt_field`` helpers. TLS in transit is enforced by
the boot gate (``require_tls``) in the headers module.
"""
from __future__ import annotations

from ..crypto import load_key
from ..exceptions import BootSelfCheckError
from .base import Module


class EncryptionModule(Module):
    name = "encryption"
    asvs = "V6"
    owasp = "A02:2021"
    wraps = "cryptography (AES-256-GCM)"

    def self_check(self) -> None:
        key = self.config.field_encryption_key
        if key:
            try:
                load_key(key)  # must decode to exactly 32 bytes
            except Exception as exc:
                raise BootSelfCheckError(f"AEGIS_FIELD_ENCRYPTION_KEY is invalid: {exc}") from exc
        # No key => field encryption helper is simply unavailable (engine raises if used).
        # That is acceptable; the README flags enabling it for PII workloads.
