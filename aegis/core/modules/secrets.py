"""Module 5 — Secrets & key management.

ASVS V6.4 / V2.10 · OWASP A02/A05. Loads secrets from env/secret-manager ONLY and
**refuses to boot** on a hardcoded, missing, empty, or weak secret in production.
Redaction of secrets from logs is enforced globally in :mod:`aegis.core.redaction`.
"""
from __future__ import annotations

from ...config.defaults import SECRET_DENYLIST
from ..exceptions import SecretError
from .base import Module


class SecretsModule(Module):
    name = "secrets"
    asvs = "V6.4, V2.10"
    owasp = "A02/A05:2021"
    wraps = "os.environ (no hardcoded secrets)"

    def self_check(self) -> None:
        cfg = self.config
        if cfg.is_production:
            if not cfg.secret_key:
                raise SecretError("AEGIS_SECRET_KEY is required in production (refusing to boot).")
            if cfg._ephemeral_secret:
                raise SecretError("Refusing an ephemeral/generated secret in production.")
            if len(cfg.secret_key) < 32:
                raise SecretError("AEGIS_SECRET_KEY must be >= 32 characters in production.")
            if cfg.secret_key.strip().lower() in SECRET_DENYLIST:
                raise SecretError("AEGIS_SECRET_KEY is a known weak/placeholder value.")
