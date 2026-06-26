"""Module 11 (tooling) — Supply-chain: SBOM generation. ADVISORY ONLY.

ASVS V14.2 · OWASP A06 (Vulnerable & Outdated Components). Emits a CycloneDX-style
SBOM of installed distributions. Never modifies the host project — it only reports.
Pair with `pip-audit` (CVE scan) and `bandit` (SAST) in CI; see .github/workflows.

Usage:  python supplychain/sbom.py > sbom.json
"""
from __future__ import annotations

import datetime as _dt
import json
import sys
from importlib import metadata


def generate_sbom() -> dict:
    components = []
    for dist in metadata.distributions():
        try:
            name = dist.metadata["Name"]
            version = dist.version
        except Exception:
            continue
        if not name:
            continue
        components.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name.lower()}@{version}",
        })
    components.sort(key=lambda c: c["name"].lower())
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "tools": [{"vendor": "AEGIS", "name": "aegis-sbom", "version": "0.1.0"}],
        },
        "components": components,
    }


if __name__ == "__main__":
    json.dump(generate_sbom(), sys.stdout, indent=2)
    sys.stdout.write("\n")
