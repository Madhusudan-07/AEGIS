#!/usr/bin/env python3
"""Live DAST probe — attacks a running AEGIS-protected instance (Subsystem A).

Sends real malicious requests and asserts AEGIS blocks them. Writes a JSON report and
exits non-zero if any probe fails (the daily workflow runs this report-only initially).
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

import jwt


def _request(method: str, url: str, headers: dict | None = None):
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        resp = urllib.request.urlopen(req, timeout=5)  # nosec B310 - fixed localhost target
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}


def run(base: str) -> list[dict]:
    results: list[dict] = []

    def check(name: str, ok: bool, detail: str = ""):
        results.append({"check": name, "result": "PASS" if ok else "FAIL", "detail": detail})

    # 1. Security headers present on a public route.
    status, headers = _request("GET", f"{base}/")
    check("public_route_up", status == 200, f"status={status}")
    check("hdr_x_content_type_options", headers.get("x-content-type-options") == "nosniff")
    check("hdr_x_frame_options", headers.get("x-frame-options") == "DENY")
    check("hdr_csp_present", "content-security-policy" in headers)

    # 2. Protected route denies an anonymous caller (deny-by-default).
    status, _ = _request("GET", f"{base}/orders")
    check("protected_denies_anonymous", status == 401, f"status={status}")

    # 3. Forged alg:none token must not authenticate.
    forged = jwt.encode({"sub": "attacker", "aud": "aegis", "iss": "aegis", "roles": ["admin"]},
                        key="", algorithm="none")
    status, _ = _request("GET", f"{base}/orders", {"Authorization": f"Bearer {forged}"})
    check("forged_alg_none_rejected", status == 401, f"status={status}")

    # 4. CORS must never wildcard / echo an untrusted origin.
    _, headers = _request("GET", f"{base}/", {"Origin": "https://evil.example.com"})
    acao = headers.get("access-control-allow-origin", "")
    check("no_wildcard_cors", acao not in ("*", "https://evil.example.com"), f"ACAO={acao!r}")

    # 5. No server-version fingerprint leaked.
    _, headers = _request("GET", f"{base}/")
    check("no_server_fingerprint", "server" not in headers or "/" not in headers.get("server", ""))

    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8000")
    ap.add_argument("--report", default="")
    args = ap.parse_args()

    results = run(args.base_url.rstrip("/"))
    failures = [r for r in results if r["result"] == "FAIL"]

    if args.report:
        import os
        os.makedirs(os.path.dirname(args.report) or ".", exist_ok=True)
        with open(args.report, "w") as fh:
            json.dump({"target": args.base_url, "results": results,
                       "failed": len(failures)}, fh, indent=2)

    for r in results:
        print(f"  [{r['result']}] {r['check']} {r['detail']}")
    print(f"\nDAST: {len(results) - len(failures)}/{len(results)} probes passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
