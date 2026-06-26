"""End-to-end proof of Requirement A (one-step connect) on the target framework.

Boots AEGIS purely by adding the middleware, then drives real requests through
Django's test client: security headers applied, deny-by-default authz enforced,
valid token allowed.
"""
from __future__ import annotations

import pytest

django = pytest.importorskip("django")

from django.conf import settings  # noqa: E402

if not settings.configured:
    settings.configure(
        DEBUG=False,
        SECRET_KEY="django-only-key-not-aegis",
        ALLOWED_HOSTS=["*"],
        ROOT_URLCONF="tests.test_django_integration",
        MIDDLEWARE=["aegis.adapters.django_adapter.AegisMiddleware"],
        DATABASES={},
        USE_TZ=True,
    )
    django.setup()

from django.http import HttpResponse, JsonResponse  # noqa: E402
from django.urls import path  # noqa: E402

import aegis  # noqa: E402
from aegis.adapters.django_adapter import require_permission  # noqa: E402
from aegis.core.config import AegisConfig  # noqa: E402
from aegis.core.crypto import generate_field_key  # noqa: E402
from aegis.core.policy import Policy  # noqa: E402


def public(request):
    return HttpResponse("ok")


@require_permission("orders:read")
def orders(request):
    return JsonResponse({"orders": []})


urlpatterns = [
    path("", public),
    path("orders", orders),
]


@pytest.fixture(autouse=True)
def boot_aegis():
    aegis.reset_engine()
    cfg = AegisConfig(environment="development", secret_key="k" * 48,
                      field_encryption_key=generate_field_key())
    aegis.secure(cfg, policy=Policy().grant("admin", "orders:*"))
    yield
    aegis.reset_engine()


@pytest.fixture
def client():
    from django.test import Client
    return Client()


def test_public_endpoint_gets_security_headers(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp["X-Content-Type-Options"] == "nosniff"
    assert resp["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in resp


def test_protected_endpoint_denies_anonymous(client):
    resp = client.get("/orders")
    assert resp.status_code == 401  # deny-by-default, no token


def test_protected_endpoint_denies_wrong_role(client):
    token = aegis.get_engine().issue_token("u", roles=("user",))
    resp = client.get("/orders", HTTP_AUTHORIZATION=f"Bearer {token}")
    assert resp.status_code == 403


def test_protected_endpoint_allows_admin(client):
    token = aegis.get_engine().issue_token("u", roles=("admin",))
    resp = client.get("/orders", HTTP_AUTHORIZATION=f"Bearer {token}")
    assert resp.status_code == 200
    assert resp.json() == {"orders": []}
