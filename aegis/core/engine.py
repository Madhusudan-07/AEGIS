"""The framework-agnostic engine: ALL security logic + orchestration + boot self-check.

* :meth:`Engine.boot` runs the **fail-closed** boot self-check (spec §10): structural
  config validation, then each module's ``self_check``. Any unsafe finding raises
  ``BootSelfCheckError`` and the app does not start.
* :meth:`Engine.handle_request` runs the request pipeline; the first
  ``SecurityViolation`` (or any unexpected error) denies, fail-closed.
* :meth:`Engine.handle_response` decorates the outbound response (headers, cookies).

Adapters are the only thing that touches a framework; they call exactly these methods.
"""
from __future__ import annotations

from .config import AegisConfig
from .context import RequestContext, ResponseContext
from .crypto import FieldCipher, TokenService, hash_password, verify_password
from .exceptions import BootSelfCheckError, SecurityViolation
from .modules.anomaly import AnomalyModule
from .modules.audit import AuditLog, AuditModule
from .egress import SsrfGuard
from .modules.authn import AuthnModule
from .modules.authz import AuthzModule
from .modules.deception import DeceptionModule
from .modules.encryption import EncryptionModule
from .modules.errors import ErrorsModule
from .modules.headers import HeadersModule
from .modules.ratelimit import RateLimitModule
from .modules.secrets import SecretsModule
from .modules.session import SessionModule
from .modules.validation import ValidationModule
from .policy import Policy
from .stores import build_store

# Canonical pipeline order. Earlier = runs first on the request (DoS guards before
# expensive work), and last on the response (so headers wrap everything).
_MODULE_ORDER: list[tuple[str, type]] = [
    ("secrets", SecretsModule),
    ("headers", HeadersModule),       # resolves trusted client IP early
    ("deception", DeceptionModule),   # cut off honeypot-trapped IPs before anything else
    ("ratelimit", RateLimitModule),   # per-IP DoS guard before auth
    ("authn", AuthnModule),           # populate identity from credential
    ("authz", AuthzModule),           # deny-by-default on required permission
    ("validation", ValidationModule),
    ("session", SessionModule),       # CSRF on state-changing methods
    ("anomaly", AnomalyModule),
    ("encryption", EncryptionModule),
    ("audit", AuditModule),
    ("errors", ErrorsModule),
]


def build_modules(config: AegisConfig, engine: "Engine") -> list:
    return [cls(config, engine) for name, cls in _MODULE_ORDER if config.module_enabled(name)]


class Engine:
    def __init__(self, config: AegisConfig, *, policy: Policy | None = None,
                 alert_sinks=None, audit_sink=None):
        self.config = config
        self.policy = policy or Policy()
        self.alert_sinks = list(alert_sinks or [])
        self._audit_sink = audit_sink
        self._booted = False
        # core services (built at boot)
        self.store = None
        self.audit: AuditLog | None = None
        self.tokens: TokenService | None = None
        self.cipher: FieldCipher | None = None
        self.ssrf: SsrfGuard | None = None
        self._modules: list = []

    # ------------------------------------------------------------------ boot
    def boot(self) -> "Engine":
        cfg = self.config
        cfg.validate()  # structural; raises ConfigError

        # core services
        self.store = build_store(cfg)
        self.audit = AuditLog(sink=self._audit_sink, enabled=cfg.module_enabled("audit"))
        if cfg.module_enabled("authn"):
            self.tokens = TokenService(
                cfg.secret_key, algorithm=cfg.jwt_algorithm, issuer=cfg.jwt_issuer,
                audience=cfg.jwt_audience, leeway=cfg.jwt_leeway, public_key=cfg.jwt_public_key,
            )
        if cfg.module_enabled("encryption") and cfg.field_encryption_key:
            try:
                self.cipher = FieldCipher(cfg.field_encryption_key)
            except Exception as exc:  # invalid key -> refuse to boot
                raise BootSelfCheckError(f"invalid field encryption key: {exc}") from exc

        # SSRF egress guard is always available (no secret needed); the app opts in by
        # calling engine.check_egress() before any server-side fetch.
        self.ssrf = SsrfGuard(
            allowed_schemes=cfg.egress_allowed_schemes,
            allow_http=cfg.egress_allow_http,
            host_allowlist=cfg.egress_host_allowlist,
        )

        self._modules = build_modules(cfg, self)

        # FAIL-CLOSED boot self-check: any unsafe finding aborts startup.
        for module in self._modules:
            module.self_check()

        self._booted = True
        self.audit.record(
            "aegis.boot", outcome="ok", environment=cfg.environment,
            modules=[m.name for m in self._modules], asvs_target="L2",
        )
        return self

    @property
    def booted(self) -> bool:
        return self._booted

    def module(self, name: str):
        """Return the enabled module instance with ``name``, or None if disabled."""
        for m in self._modules:
            if m.name == name:
                return m
        return None

    def login(self, identifier: str, password: str, stored_hash: str, *, ip: str = "", roles=()):
        """One-call password login: lockout-aware, enumeration-safe, audited.

        Returns an access token on success; raises ``AuthenticationError`` otherwise.
        Always call it the same way for unknown users (pass a decoy hash) so timing
        and responses do not reveal whether an account exists.
        """
        authn = self.module("authn")
        if authn is None:
            raise BootSelfCheckError("authn module disabled")
        authn.login(identifier, password, stored_hash, ip=ip)
        return self.issue_token(identifier, roles=roles)

    # --------------------------------------------------------------- request
    def handle_request(self, ctx: RequestContext) -> ResponseContext | None:
        """Run the pipeline. Return a ResponseContext to DENY, or None to allow."""
        if not self._booted:
            raise BootSelfCheckError("Engine.handle_request called before boot()")
        try:
            for module in self._modules:
                module.process_request(ctx)
        except SecurityViolation as violation:
            return self._deny(ctx, violation)
        except Exception as unexpected:  # noqa: BLE001 - fail closed on ANY surprise
            return self._deny(ctx, SecurityViolation("internal security error"),
                              internal=unexpected)
        return None

    def handle_response(self, ctx: RequestContext, resp: ResponseContext) -> ResponseContext:
        for module in reversed(self._modules):
            try:
                module.process_response(ctx, resp)
            except Exception:  # response decoration must never crash the app
                if self.audit:
                    self.audit.record("aegis.response_decorate_error",
                                      correlation_id=ctx.correlation_id, module=module.name)
        return resp

    def _deny(self, ctx: RequestContext, violation: SecurityViolation, internal=None) -> ResponseContext:
        # ErrorsModule owns the safe client body; here we build the default and let
        # the headers module still harden the denial response.
        resp = ResponseContext(
            status=violation.status_code,
            body={"error": violation.public_message, "correlation_id": ctx.correlation_id},
        )
        for module in self._modules:
            if module.name in ("headers", "errors"):
                try:
                    module.process_response(ctx, resp)
                except Exception:  # nosec B110 - hardening a denial must never crash
                    pass
        retry = getattr(violation, "retry_after", None)
        if retry:
            resp.set_header("Retry-After", str(retry))
        if self.audit:
            self.audit.record(
                "aegis.deny", outcome="deny", correlation_id=ctx.correlation_id,
                violation=type(violation).__name__, status=violation.status_code,
                method=ctx.method, path=ctx.path, client_ip=ctx.client_ip,
                subject=ctx.identity.subject,
                detail=str(violation),
                internal=repr(internal) if internal is not None else None,
            )
        return resp

    # ----------------------------------------------------------------- alerts
    def alert(self, kind: str, **fields) -> None:
        """Emit to developer-configured sinks ONLY (no phone-home, spec Principle 7)."""
        if self.audit:
            self.audit.record("aegis.alert", kind=kind, **fields)
        for sink in self.alert_sinks:
            try:
                sink(kind, fields)
            except Exception:  # nosec B110 - a failing alert sink must not break requests
                pass

    # ------------------------------------------------- public crypto helpers
    def issue_token(self, subject: str, *, roles=(), token_type: str = "access",
                    ttl: int | None = None, extra: dict | None = None) -> str:
        if not self.tokens:
            raise BootSelfCheckError("authn module disabled; no token service")
        ttl = ttl if ttl is not None else (
            self.config.access_ttl if token_type == "access" else self.config.refresh_ttl  # nosec B105 - token-type label, not a secret
        )
        return self.tokens.issue(subject, ttl=ttl, roles=roles, token_type=token_type, extra=extra)

    @staticmethod
    def hash_password(password: str) -> str:
        return hash_password(password)

    @staticmethod
    def verify_password(stored_hash: str, password: str) -> bool:
        return verify_password(stored_hash, password)

    def encrypt_field(self, plaintext, *, aad: bytes = b"") -> str:
        if not self.cipher:
            raise BootSelfCheckError("encryption module disabled or no key configured")
        return self.cipher.encrypt(plaintext, aad=aad)

    def decrypt_field(self, token: str, *, aad: bytes = b"") -> bytes:
        if not self.cipher:
            raise BootSelfCheckError("encryption module disabled or no key configured")
        return self.cipher.decrypt(token, aad=aad)

    def check_egress(self, url: str) -> dict:
        """SSRF guard (closes G2): validate an outbound URL before the app fetches it.

        Returns ``{"url", "host", "addresses"}`` if safe; raises ``EgressBlocked`` if the
        target resolves to a loopback/private/link-local/metadata address or a
        disallowed scheme/host. Call this before any server-side fetch of a user URL.
        """
        if not self.ssrf:
            raise BootSelfCheckError("Engine.check_egress called before boot()")
        return self.ssrf.check(url)
