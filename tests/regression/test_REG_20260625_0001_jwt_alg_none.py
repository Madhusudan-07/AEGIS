"""Regression REG-20260625-0001 — a forged JWT ``alg:none`` must never authenticate.

Threat: STRIDE S1 (Spoofing) / abuse case AC2 (forged-token elevation).
This is the seed entry of the append-only corpus; it demonstrates the convention.
Once locked, this file may not be weakened without a logged human override.
"""
from __future__ import annotations

import jwt

from tests.helpers import build_engine, make_ctx


def test_reg_20260625_0001_alg_none_rejected():
    engine = build_engine()
    forged = jwt.encode(
        {"sub": "attacker", "aud": "aegis", "iss": "aegis", "roles": ["admin"]},
        key="", algorithm="none",
    )
    ctx = make_ctx(path="/orders", headers={"Authorization": f"Bearer {forged}"})
    ctx.state["require_permission"] = "orders:read"
    deny = engine.handle_request(ctx)
    assert deny is not None and deny.status == 401
