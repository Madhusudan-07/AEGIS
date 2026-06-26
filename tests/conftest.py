"""Shared fixtures for the AEGIS test suite (helpers live in tests/helpers.py)."""
from __future__ import annotations

import pytest

from tests.helpers import build_engine


@pytest.fixture
def alerts():
    return []


@pytest.fixture
def engine(alerts):
    return build_engine(alerts=alerts)
