"""SSRF egress guard (closes threat-model gap G2)."""
from __future__ import annotations

import pytest

from aegis.core.egress import SsrfGuard
from aegis.core.exceptions import EgressBlocked


def test_blocks_cloud_metadata_endpoint():
    g = SsrfGuard(allow_http=True)
    with pytest.raises(EgressBlocked):
        g.check("http://169.254.169.254/latest/meta-data/iam/security-credentials/")


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/",
    "http://[::1]/",
    "http://10.0.0.5/internal",
    "http://192.168.1.1/",
    "http://172.16.0.10/",
    "http://169.254.1.1/",       # link-local
    "http://0.0.0.0/",           # unspecified
])
def test_blocks_internal_literal_ips(url):
    with pytest.raises(EgressBlocked):
        SsrfGuard(allow_http=True).check(url)


@pytest.mark.parametrize("url", [
    "http://example.com/",       # http disallowed by default
    "file:///etc/passwd",
    "gopher://evil/",
    "ftp://internal/",
])
def test_scheme_allowlist_blocks_non_https(url):
    # Scheme is rejected before any DNS resolution happens (no network hit).
    with pytest.raises(EgressBlocked):
        SsrfGuard().check(url)


def test_dns_resolving_to_private_is_blocked():
    # DNS-based SSRF: a public-looking host that resolves to an internal address.
    g = SsrfGuard(allow_http=True, resolver=lambda host: ["10.0.0.5"])
    with pytest.raises(EgressBlocked):
        g.check("http://totally-legit.example.com/")


def test_allows_genuine_public_https():
    g = SsrfGuard(resolver=lambda host: ["93.184.216.34"])  # example.com's public IP
    result = g.check("https://example.com/some/path")
    assert result["host"] == "example.com"
    assert "93.184.216.34" in result["addresses"]


def test_host_allowlist_is_enforced():
    g = SsrfGuard(host_allowlist=["api.partner.example"], resolver=lambda host: ["93.184.216.34"])
    with pytest.raises(EgressBlocked):
        g.check("https://example.com/")                     # not on the allow-list
    assert g.check("https://api.partner.example/")["host"] == "api.partner.example"


def test_rejects_missing_host():
    with pytest.raises(EgressBlocked):
        SsrfGuard(allow_http=True).check("http:///no-host")


def test_engine_exposes_check_egress(engine):
    with pytest.raises(EgressBlocked):
        engine.check_egress("http://169.254.169.254/")
