"""Adapters — the ONLY framework-specific code (Requirement B).

A new stack = one new adapter that builds a :class:`~aegis.core.context.RequestContext`
and applies a :class:`~aegis.core.context.ResponseContext`. Zero changes to ``core/``.
"""
from .base import Adapter

__all__ = ["Adapter"]
