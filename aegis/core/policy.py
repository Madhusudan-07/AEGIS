"""Centralized RBAC policy engine — **deny by default** (spec Principle 4, ASVS V4).

A single, in-process evaluation point (no scattered ``if user.is_admin`` checks).
Unknown role, unknown permission, empty policy, or any evaluation error all resolve
to **deny**. Permissions support a namespace wildcard (``orders:*``) and global ``*``.
"""
from __future__ import annotations

from typing import Iterable, Mapping


class Policy:
    def __init__(self) -> None:
        self._role_perms: dict[str, set[str]] = {}
        self._inherits: dict[str, set[str]] = {}

    # --- construction --------------------------------------------------------
    def grant(self, role: str, *permissions: str) -> "Policy":
        self._role_perms.setdefault(role, set()).update(permissions)
        return self

    def inherit(self, role: str, parent: str) -> "Policy":
        self._inherits.setdefault(role, set()).add(parent)
        return self

    def load(self, mapping: Mapping[str, Iterable[str]]) -> "Policy":
        """Load ``{role: [permissions...]}``. Strings prefixed ``@`` mean 'inherit role'."""
        for role, perms in mapping.items():
            for p in perms:
                if p.startswith("@"):
                    self.inherit(role, p[1:])
                else:
                    self.grant(role, p)
        return self

    # --- evaluation ----------------------------------------------------------
    def _effective(self, role: str, _seen: set[str] | None = None) -> set[str]:
        seen = _seen or set()
        if role in seen:
            return set()
        seen.add(role)
        perms = set(self._role_perms.get(role, ()))
        for parent in self._inherits.get(role, ()):
            perms |= self._effective(parent, seen)
        return perms

    def permissions_for(self, roles: Iterable[str]) -> set[str]:
        out: set[str] = set()
        for r in roles:
            out |= self._effective(r)
        return out

    def allows(self, roles: Iterable[str], permission: str) -> bool:
        """Return True ONLY if an explicit grant covers ``permission``. Else deny."""
        try:
            granted = self.permissions_for(roles)
        except Exception:
            return False  # fail closed on any policy error
        if "*" in granted or permission in granted:
            return True
        # namespace wildcard: a grant of "orders:*" covers "orders:read"
        if ":" in permission:
            ns = permission.split(":", 1)[0]
            if f"{ns}:*" in granted:
                return True
        return False
