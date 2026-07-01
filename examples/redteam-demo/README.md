# AEGIS Red-Team Demo — watch it defend, live

The **same** SecureNotes API, built two ways, attacked by a red-team harness:

- [`vulnerable_app.py`](vulnerable_app.py) — a naive build (every weakness labelled `# VULN:`)
- [`secure_app.py`](secure_app.py) — the same features, built with AEGIS

Diff the two files and you'll see the difference isn't scattered security code — it's the
AEGIS middleware plus a few declarative decorators. The business logic stays clean.

## Run it (one command)

```bash
pip install -e ".[django]"            # from the repo root, if not already
python examples/redteam-demo/run_demo.py
```

That boots both builds and fires the harness. (Or run each in its own terminal:
`vulnerable_app.py` → :8000, `secure_app.py` → :8001, then `redteam.py`.)

## What you see

```
  #  ATTACK                               UNPROTECTED                AEGIS
  1  Forged admin token                   BREACHED (200)             BLOCKED (401)
  2  Broken access control (user->admin)  BREACHED (200)             BLOCKED (403)
  3  Mass assignment (role=admin)         BREACHED (200)             BLOCKED (400)
  4  Clickjacking/sniffing headers        MISSING                    PRESENT
  5  SSRF -> internal address             BREACHED (200)             BLOCKED (400)
  6  Brute-force login (20 tries)         NO LOCKOUT (20/20 tried)   LOCKED after 6
  7  Request flood (250 reqs)             ALL 250 served (no limit)  RATE-LIMITED (~req 187)
  8  Scanner probes honeypot (/.env)      still served (200)         IP BLOCKED (404)
  DEFENDED:  unprotected 0/8    |    AEGIS 8/8
```

## The eight attacks

| # | Attack | Naive build | AEGIS control |
|---|--------|-------------|---------------|
| 1 | Fabricate an admin token without an account | trusts a client-forged token | AuthN verifies the JWT; `alg:none`/forged → 401 |
| 2 | A real low-priv user hits an admin endpoint | no authz check (authn ≠ authz) | AuthZ **deny-by-default** via `@require_permission` → 403 |
| 3 | Sneak `role: admin` into a profile update | mass-assigns every field | Validation rejects unknown fields → 400 |
| 4 | Clickjacking / MIME sniffing | no security headers | Strict headers injected (X-Frame-Options, CSP, …) |
| 5 | **SSRF** — coerce a fetch to an internal address | fetches any URL | **Egress guard** rejects loopback/private/metadata → 400 |
| 6 | Brute-force a password | unlimited attempts | Argon2id + **lockout with backoff** after 5 |
| 7 | Flood the service | every request served | Per-IP **rate limiting** → 429 |
| 8 | Scan for `/.env` (recon) | 404, keeps roaming | **Honeypot** traps + blocklists the IP everywhere → 404 |

## ⚠️ Honest scope — what this does and does NOT show

This is the part a real reviewer cares about. AEGIS is a **perimeter + primitives** layer,
not a magic wrapper. Precisely:

- **What AEGIS stops here (the 8 above):** authentication, authorization, input validation,
  headers, SSRF egress, brute-force, rate limiting, and scanner deception — perimeter
  controls that hold regardless of the app's internals.
- **The SSRF guard has an honest limit:** it validates the URL *at call time* and blocks
  internal/metadata targets, but a DNS-rebinding/TOCTOU attacker or a permissive host
  network can still reach internal services — true egress control also needs network-layer
  policy. It removes the common vectors; it is not a substitute for an egress firewall.
- **The honeypot advances detection, it isn't omniscient:** it cheaply removes the noisy
  scanners that make up most traffic, but a careful low-and-slow attacker who avoids the
  decoys won't trip it (threat-model gap G3 — *advanced*, not closed).
- **What still needs the app's cooperation** (defense-in-depth, *not* shown as AEGIS wins,
  on purpose):
  - **IDOR / object ownership** — AEGIS authorizes *actions* (`notes:read`), but "is this
    note *yours*?" must be enforced by the app scoping its queries to the current user.
  - **SQL injection** — the real defense is parameterized queries / the ORM. AEGIS validates
    at the boundary as a second layer; it does not make raw SQL safe.
  - **CSRF** — deliberately excluded: this is a **Bearer-token** API, which is not a CSRF
    target. AEGIS provides CSRF protection for **cookie-based** flows; claiming it here would
    be misleading.
- **The "before" is a naive build, not the same code minus one line.** Real security also
  means *using* AEGIS's vetted helpers (Argon2 passwords, real JWTs, lockout) instead of the
  rolled-your-own versions in `vulnerable_app.py`.

In short: AEGIS raises the floor dramatically and removes whole classes of common mistakes —
but it is a layer in a defense-in-depth strategy, not a substitute for writing the app
correctly or for an external pentest. (Same honesty as the top-level README.)
