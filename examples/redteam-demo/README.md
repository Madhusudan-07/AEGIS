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
  5  Brute-force login (20 tries)         NO LOCKOUT (20/20 tried)   LOCKED after 6
  6  Request flood (250 reqs)             ALL 250 served (no limit)  RATE-LIMITED (~req 188)
  DEFENDED:  unprotected 0/6    |    AEGIS 6/6
```

## The six attacks

| # | Attack | Naive build | AEGIS control |
|---|--------|-------------|---------------|
| 1 | Fabricate an admin token without an account | trusts a client-forged token | AuthN verifies the JWT; `alg:none`/forged → 401 |
| 2 | A real low-priv user hits an admin endpoint | no authz check (authn ≠ authz) | AuthZ **deny-by-default** via `@require_permission` → 403 |
| 3 | Sneak `role: admin` into a profile update | mass-assigns every field | Validation rejects unknown fields → 400 |
| 4 | Clickjacking / MIME sniffing | no security headers | Strict headers injected (X-Frame-Options, CSP, …) |
| 5 | Brute-force a password | unlimited attempts | Argon2id + **lockout with backoff** after 5 |
| 6 | Flood the service | every request served | Per-IP **rate limiting** → 429 |

## ⚠️ Honest scope — what this does and does NOT show

This is the part a real reviewer cares about. AEGIS is a **perimeter + primitives** layer,
not a magic wrapper. Precisely:

- **What AEGIS stops here (the 6 above):** authentication, authorization, input validation,
  headers, brute-force, and rate limiting — perimeter controls that hold regardless of the
  app's internals.
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
