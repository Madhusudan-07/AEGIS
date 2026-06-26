"""Base class every security module extends."""
from __future__ import annotations

from ..context import RequestContext, ResponseContext


class Module:
    #: stable identifier used for toggles, ordering, and audit.
    name: str = "base"
    #: doc-only: ASVS section(s) and OWASP Top-10 category this module addresses.
    asvs: str = ""
    owasp: str = ""
    #: doc-only: the vetted library this module wraps (or "" if pure orchestration).
    wraps: str = ""

    def __init__(self, config, engine) -> None:
        self.config = config
        self.engine = engine

    def self_check(self) -> None:
        """Boot-time gate. Raise ``BootSelfCheckError`` if the environment is unsafe."""

    def process_request(self, ctx: RequestContext) -> None:
        """Inspect/deny an inbound request. Raise ``SecurityViolation`` to deny."""

    def process_response(self, ctx: RequestContext, resp: ResponseContext) -> None:
        """Decorate the outbound response (headers, cookies). Must not raise to deny."""
