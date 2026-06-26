"""Framework-agnostic request/response context.

Adapters translate a framework request (Django ``HttpRequest``, a WSGI environ, …)
into a :class:`RequestContext`; the core engine only ever sees this neutral type.
This is the seam that makes AEGIS plug-and-play (Requirement B): a new stack means a
new adapter that builds one of these, with zero changes to ``core/``.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Identity:
    """The authenticated principal, set by the AuthN module. ``None`` subject = anonymous."""

    subject: str | None = None
    roles: tuple[str, ...] = ()
    claims: dict[str, Any] = field(default_factory=dict)
    authenticated: bool = False


@dataclass
class RequestContext:
    method: str
    path: str
    # Header keys are normalized to lowercase by the adapter.
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    query: dict[str, Any] = field(default_factory=dict)
    body: Any = None
    # ``client_ip`` is the *vetted* peer address (see headers module / trusted proxies).
    client_ip: str = ""
    raw_remote_addr: str = ""
    forwarded_for: tuple[str, ...] = ()
    scheme: str = "http"

    identity: Identity = field(default_factory=Identity)
    correlation_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    # Inter-module scratch space (e.g. authz can read what authn wrote).
    state: dict[str, Any] = field(default_factory=dict)

    @property
    def is_secure(self) -> bool:
        return self.scheme == "https"


@dataclass
class ResponseContext:
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = None
    # Cookies to set: name -> dict of cookie attributes (value, httponly, secure, samesite…)
    set_cookies: dict[str, dict[str, Any]] = field(default_factory=dict)

    def set_header(self, name: str, value: str) -> None:
        self.headers[name] = value
