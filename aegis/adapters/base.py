"""The adapter contract. Implement these two translations for any framework."""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..core.context import RequestContext, ResponseContext


class Adapter(ABC):
    @abstractmethod
    def build_context(self, request) -> RequestContext:
        """Translate a framework request into a neutral RequestContext."""

    @abstractmethod
    def apply_response(self, ctx: RequestContext, resp: ResponseContext, framework_response):
        """Apply headers/cookies from a ResponseContext onto a framework response."""

    @staticmethod
    def normalize_headers(items) -> dict[str, str]:
        """Lowercase header keys for stable, case-insensitive lookups in core."""
        return {str(k).lower(): str(v) for k, v in items}
