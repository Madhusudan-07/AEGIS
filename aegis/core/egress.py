"""SSRF egress guard — validate an outbound URL before the app fetches it.

Closes threat-model gap **G2** (was advisory). ASVS V5.2.6 · OWASP A10 (SSRF).

Any feature that fetches a user-supplied URL (link previews, webhooks, avatar imports…)
is an SSRF vector: an attacker points it at ``http://169.254.169.254/`` (the cloud
metadata endpoint) or an internal service. :class:`SsrfGuard` refuses those:

* enforces a scheme allow-list (https by default);
* resolves DNS and validates **every** resolved address — not just the hostname —
  which defeats DNS-based SSRF;
* blocks loopback, private, link-local (incl. the metadata IPs), reserved, multicast,
  and unspecified addresses;
* optional host allow-list for the strict case.

**Honest limit:** this is *call-time* validation and it returns the resolved addresses so
the caller can pin them, but a TOCTOU / DNS-rebinding attacker or a permissive host
network can still reach internal services. It removes the common SSRF vectors; it is not
a substitute for a locked-down egress firewall. (Documented, not hidden.)
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from .exceptions import EgressBlocked

# Cloud instance-metadata service addresses (AWS/GCP/Azure/OpenStack all share these).
_METADATA_IPS = {"169.254.169.254", "fd00:ec2::254"}


def _forbidden(ip: ipaddress._BaseAddress) -> bool:
    return (
        ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved
        or ip.is_multicast or ip.is_unspecified or str(ip) in _METADATA_IPS
    )


class SsrfGuard:
    def __init__(self, *, allowed_schemes=("https",), allow_http: bool = False,
                 host_allowlist=(), resolver=None):
        schemes = {s.lower() for s in allowed_schemes}
        if allow_http:
            schemes.add("http")
        self.allowed_schemes = schemes
        self.host_allowlist = set(host_allowlist)
        self._resolve = resolver or self._default_resolver

    @staticmethod
    def _default_resolver(host: str) -> list[str]:
        infos = socket.getaddrinfo(host, None)
        return sorted({info[4][0] for info in infos})

    def check(self, url: str) -> dict:
        """Return ``{"url", "host", "addresses"}`` if safe; raise :class:`EgressBlocked`."""
        parsed = urlparse(url)
        if parsed.scheme.lower() not in self.allowed_schemes:
            raise EgressBlocked(f"scheme not allowed: {parsed.scheme!r}")
        host = parsed.hostname
        if not host:
            raise EgressBlocked("URL has no host")
        if self.host_allowlist and host not in self.host_allowlist:
            raise EgressBlocked(f"host not in allow-list: {host}")

        # Literal IP? validate directly. Otherwise resolve and validate every address.
        try:
            addresses = [str(ipaddress.ip_address(host))]
        except ValueError:
            try:
                addresses = self._resolve(host)
            except Exception as exc:
                raise EgressBlocked(f"could not resolve host: {host}") from exc

        if not addresses:
            raise EgressBlocked(f"no addresses for host: {host}")
        for addr in addresses:
            if _forbidden(ipaddress.ip_address(addr)):
                raise EgressBlocked(f"target resolves to a forbidden address: {addr}")
        return {"url": url, "host": host, "addresses": addresses}
