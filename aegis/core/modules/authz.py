"""Module 2 — Authorization (RBAC, deny-by-default).

ASVS V4 · OWASP A01 (Broken Access Control). A single evaluation point: the route
declares a required permission (via ``@require_permission`` -> ``ctx.state``), and this
module consults the centralized :class:`~aegis.core.policy.Policy`. Missing identity,
missing grant, or any policy error all DENY.
"""
from __future__ import annotations

from ..exceptions import AuthenticationError, AuthorizationError
from .base import Module


class AuthzModule(Module):
    name = "authz"
    asvs = "V4"
    owasp = "A01:2021"
    wraps = "core Policy engine (deny-by-default)"

    def process_request(self, ctx) -> None:
        required = ctx.state.get("require_permission")
        if required is None:
            return  # route did not declare a permission -> not gated here

        # Zero-trust: you must be authenticated before you can be authorized.
        if not ctx.identity.authenticated:
            raise AuthenticationError("authentication required for protected resource")

        needed = (required,) if isinstance(required, str) else tuple(required)
        roles = ctx.identity.roles
        # require ALL listed permissions (least privilege); deny-by-default.
        for perm in needed:
            if not self.engine.policy.allows(roles, perm):
                self.engine.audit.record(
                    "authz.deny", subject=ctx.identity.subject, permission=perm,
                    roles=list(roles), path=ctx.path, correlation_id=ctx.correlation_id,
                )
                self.engine.alert("authz.deny", subject=ctx.identity.subject, permission=perm)
                raise AuthorizationError(f"missing permission: {perm}")
