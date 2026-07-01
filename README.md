# AEGIS — plug-and-play security layer (Python / Django)

A **secure-by-default, fail-closed, zero-trust** security layer your Django app adopts
in **one step**. Strength comes from defense-in-depth + vetted, audited components +
adversarial verification — not a single trick, and not self-assertion.

> Graded to **OWASP ASVS L2 (standard)** · maps to **OWASP Top 10 (2021)** · data
> sensitivity **PII** · external threat actors. Full threat model: [THREAT_MODEL.md](THREAT_MODEL.md).

---

## Quickstart — the one step (Requirement A)

```bash
pip install "aegis-security[django,redis,sanitize]"
```

```python
# settings.py
MIDDLEWARE = [
    "aegis.adapters.django_adapter.AegisMiddleware",   # <-- the only required line
    # ...your existing middleware...
]
```

That's it. On startup AEGIS auto-detects the environment, boots every module with
hardened defaults, and **refuses to start** if the environment is unsafe (missing
secret, wildcard CORS in prod, `DEBUG=True` in prod, TLS not expected). Set the
required production secrets first (see [`.env.example`](.env.example)):

```bash
export AEGIS_ENV=production
export AEGIS_SECRET_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')"
export AEGIS_FIELD_ENCRYPTION_KEY="$(python -c 'from aegis.core.crypto import generate_field_key;print(generate_field_key())')"
export AEGIS_CORS_ORIGINS="https://app.example.com"
export AEGIS_REDIS_URL="redis://localhost:6379/0"
```

Non-Django / any field (Requirement B):

```python
from aegis import secure
handle = secure()                       # boots the global engine, fails closed if unsafe
from aegis.adapters.generic import protect
deny = protect(handle.engine, {"method": "GET", "path": "/", "remote_addr": "1.2.3.4"})
```

### Protecting views (deny-by-default authz)

```python
from aegis.adapters.django_adapter import require_auth, require_permission, validate_body

@require_permission("orders:read")          # 401 if unauthenticated, 403 if missing grant
def list_orders(request): ...

@validate_body({"name": str})               # rejects unknown fields (mass-assignment guard)
def update_profile(request): ...
```

Declare the RBAC policy once, at boot:

```python
from aegis import secure
from aegis.core.policy import Policy

policy = (Policy()
    .grant("admin", "orders:*", "users:read")
    .grant("auditor", "orders:read")
    .inherit("manager", "auditor"))
secure(policy=policy)                        # pass alert_sinks=/audit_sink= here too
```

### Auth + crypto helpers

```python
h = secure().hash_password("pw")                       # Argon2id
token = secure().login("a@b.com", "pw", h, roles=("admin",))  # lockout-aware, enumeration-safe
ct = secure().encrypt_field("123-45-6789")             # AES-256-GCM (PII at rest)
```

---

## How "strong" is achieved (not asserted)

1. **Threat-model-first** — every control traces to a STRIDE threat in [THREAT_MODEL.md](THREAT_MODEL.md); gaps are flagged (G1–G4), not hidden.
2. **Vetted components only** — no hand-rolled crypto. AEGIS wraps argon2-cffi, PyJWT, and `cryptography`; the original code is orchestration + adapter glue.
3. **Fail-closed, proven** — boot refusal and downstream-outage denial are demonstrated by tests, not claimed (see `tests/test_boot_failclosed.py`, `tests/test_adversarial.py`).
4. **Adversarial corpus** — forged `alg:none`/expired/tampered tokens, CSRF, CORS abuse, rate-limit, mass-assignment, store outage — all blocked in `tests/`.
5. **SAST + dependency CVE scan + SBOM** wired into CI; build fails on critical findings.

---

## Architecture

```
aegis/
  __init__.py            # secure() — the single connect entrypoint (Requirement A)
  core/                  # framework-agnostic: ALL security logic
    engine.py            #   orchestration + fail-closed boot self-check
    config.py            #   typed, secure-by-default config (+ from_env)
    crypto.py            #   wrappers over argon2-cffi / PyJWT / cryptography (NO primitives)
    policy.py            #   RBAC engine (deny-by-default)
    stores.py            #   Redis / in-memory counter stores (fail-closed)
    redaction.py         #   strip secrets/PII from logs & errors
    modules/             #   the 12 toggleable security modules
  adapters/              # thin; the ONLY framework-specific code
    django_adapter.py    #   middleware + @require_* decorators
    generic.py           #   any-framework adapter
  config/defaults.py     # secure-by-default constants
supplychain/sbom.py      # CycloneDX SBOM generator (advisory)
.github/workflows/       # pip-audit + bandit + pytest gate
tests/                   # unit + integration + adversarial + fail-closed proofs
```

A new stack = **one new adapter** that builds a `RequestContext` and applies a
`ResponseContext`. Zero `core/` changes.

---

## Security modules → vetted library, ASVS, OWASP

| # | Module | Wraps (vetted) | ASVS | OWASP Top 10 |
|---|--------|----------------|------|--------------|
| 1 | AuthN | PyJWT (verify, alg-pinned) + argon2-cffi | V2, V3 | A07 Identification & Auth Failures |
| 2 | AuthZ (RBAC, deny-by-default) | core Policy engine | V4 | A01 Broken Access Control |
| 3 | Input validation / output encoding | bleach + stdlib | V5 | A03 Injection |
| 4 | Rate limiting / lockout | redis / in-memory | V11, V2 | A04 / A07 |
| 5 | Secrets & key management | os.environ (no hardcode) | V6, V2.10 | A02 / A05 |
| 6 | Encryption (field-level) | cryptography (AES-256-GCM) | V6 | A02 Cryptographic Failures |
| 7 | Security headers + CORS/CSP | orchestration | V14 | A05 Security Misconfiguration |
| 8 | Session & token security (CSRF) | stdlib hmac | V3 | A01 / A07 |
| 9 | Audit logging (hash-chained) | stdlib hashlib | V7 | A09 Logging Failures |
| 10 | Anomaly detection & alerting | redis counters | V7.2 | A09 |
| 11 | Supply-chain (SBOM + CVE scan) | pip-audit / bandit / CycloneDX | V14.2 | A06 Vulnerable Components |
| 12 | Safe error handling | orchestration | V7.4, V14.3 | A05 |
| 13 | Deception / honeypot (trap + blocklist scanners) | redis blocklist | V11 | A09 |
| — | SSRF egress guard *(service: `engine.check_egress`)* | stdlib `ipaddress`/`socket` | V5.2.6 | A10 SSRF |

Modules 13 + the egress guard were added in v2 to close threat-model gaps **G3** and
**G2** — see [THREAT_MODEL.md](THREAT_MODEL.md) and the live
[red-team demo](examples/redteam-demo/) (attacks 5 and 8).

Each module is independently toggleable: `AEGIS_DISABLED_MODULES=anomaly,encryption`
or `AegisConfig(enabled_modules=(...))`.

### ASVS L2 coverage summary

| ASVS area | Status | Where |
|-----------|--------|-------|
| V2 Authentication | ✅ Argon2id, lockout, enumeration-safe | `modules/authn.py` |
| V3 Session mgmt | ✅ JWT (alg-pinned), httpOnly/Secure/SameSite, CSRF | `authn.py`, `session.py` |
| V4 Access control | ✅ centralized RBAC, deny-by-default | `policy.py`, `modules/authz.py` |
| V5 Validation/encoding | ✅ schema + sanitizers; ⚠️ ORM parameterization is the app's job | `modules/validation.py` |
| V6 Cryptography | ✅ AES-256-GCM, HKDF, CSPRNG; TLS expected (boot gate) | `crypto.py` |
| V7 Errors & logging | ✅ generic errors, hash-chained audit, redaction | `errors.py`, `audit.py` |
| V11 Business logic / anti-automation | ✅ rate limit + lockout; ⚠️ business-logic abuse is G1 | `modules/ratelimit.py` |
| V14 Configuration | ✅ strict headers/CSP, no wildcard CORS, no leaky errors | `headers.py`, `errors.py` |

---

## Fail-closed behaviors (proven by tests)

| Injected failure | Behavior | Test |
|------------------|----------|------|
| Required secret missing/empty in prod | **refuse to boot** | `test_boot_failclosed.py` |
| Weak/short secret in prod | refuse to boot | ″ |
| Wildcard / non-https CORS in prod | refuse to boot | ″ |
| `require_tls=False` in prod | refuse to boot | ″ |
| Invalid field-encryption key | refuse to boot | ″ |
| Django `DEBUG=True` in prod | refuse to boot | `django_adapter.py` |
| Rate-limit / lockout store unreachable | **deny** (503), not allow-through | `test_adversarial.py` |
| JWT `alg:none` / expired / tampered / wrong-aud | reject (401) | `test_crypto.py`, `test_adversarial.py` |
| Missing permission / unknown role | deny (403) by default | `test_authz.py` |

---

## Run the checks locally

```bash
pip install -r requirements-dev.txt && pip install -e ".[django,sanitize]"
pytest -q                                  # 66 tests: unit + integration + adversarial
bandit -r aegis -c pyproject.toml -ll      # SAST gate (medium+); currently 0 findings
pip-audit -r requirements.txt --strict     # dependency CVE scan
python supplychain/sbom.py > sbom.json     # SBOM
```

---

## Forbidden anti-patterns — verified absent

Hand-rolled crypto · `alg:none`/unverified JWTs · MD5/SHA1 for passwords · predictable
tokens/IDs · secrets/PII/tokens in logs · hardcoded/committed secrets · wildcard CORS in
prod · trusting client validation alone · trusting `X-Forwarded-*` unverified · authz
default-allow · stack traces to clients · unpinned deps · disabling TLS verification.

---

## Daily self-hardening loop (CI + AI triage + ratchet)

A loop tests AEGIS every day and on every PR, and makes coverage **compound** — while
being provably unable to weaken itself or merge without a human.

**Four goals:** (1) test AEGIS daily with a real attack battery, (2) ratchet strength
upward — coverage only ever grows, (3) propose fixes + new adversarial tests by PR, with
rationale, (4) *cannot* weaken itself or merge without a human — enforced by CI, not
convention.

```
.github/workflows/
  daily-security.yml     # Subsystem A — cron battery: pip-audit, bandit, gitleaks,
                         #   adversarial corpus, fail-closed proofs, fuzzing, report-only DAST
  pr-security.yml        # per-PR battery + the REQUIRED ratchet guard
  security-agent.yml     # Subsystem B — AI triage agent (propose-only)
security/
  ratchet/               # Subsystem C — the ratchet
    ratchet_guard.py     #   required check: blocks any coverage/corpus regression
    update_corpus.py     #   the ONLY supported way to add coverage (append-only)
    baseline_tests.txt   #   tests that must always exist (grows only)
    corpus.lock.json     #   immutable regression entries (id, path, sha256, threat)
  agent/                 #   PROMPT.md (hardened) + run_agent.py (deterministic triage)
  dast/probe.py          #   live attack probe against an ephemeral instance
  loop.config.yml        #   staged rollout: report-only -> pr-only -> enforce
tests/regression/        # append-only regression corpus (test-first, per finding)
examples/demo_app/       # throwaway AEGIS-protected instance for DAST
```

**The ratchet** is the mechanism that makes "stronger over time" real *and* safe:
every confirmed vuln becomes a permanent regression test (committed before its fix); the
corpus is append-only; the required guard fails any PR that deletes/weakens a test or
control — unless a human applies the logged `security-override-approved` label. The system
is monotonic: it never regresses on anything ever found, and a human approves every merge.

**The agent proposes only.** It triages + dedupes findings, writes the regression test
first, and opens one PR per fix to a non-protected `security/auto/*` branch. It never
merges, never pushes to `main`, never deploys, never reads secrets — enforced by token
scope + branch protection (see `SECURITY.md`). All findings it ingests are treated as
untrusted (prompt-injection defense on our own security tool).

Operator setup (branch protection, the least-privilege `AEGIS_AGENT_TOKEN`, required
checks) is in [SECURITY.md](SECURITY.md); contribution + ratchet rules in
[CONTRIBUTING.md](CONTRIBUTING.md).

## ⚠️ Limitations & External Audit

**This generated code carries NO audit or attack history.** It has not survived years of
real-world attack the way the libraries it wraps have. **Do not let it guard anything
sensitive until it has been independently security-reviewed and penetration-tested** by a
qualified third party. Generated code can contain subtle logic flaws that pass tests yet
fail under a determined adversary.

What AEGIS does **NOT** cover (see THREAT_MODEL G1–G4):

- **Business-logic abuse** by a legitimately authenticated user (G1) — only rate-limit + audit + anomaly signal.
- **SSRF / egress control** (G2) — the validation helpers are advisory; true egress blocking needs infra-level network policy.
- **Sophisticated / low-and-slow attacks** (G3) — anomaly detection is heuristic (threshold/velocity), not ML; it signals, it does not guarantee blocking.
- **Injection at the data layer** — AEGIS validates at the boundary, but **you must use parameterized queries / the ORM**; it cannot retrofit safety into raw SQL you write.
- **Insider threats, physical access, host compromise, and secret-manager compromise** — explicitly out of scope.
- **DDoS at network/transport layer** — needs a CDN/WAF/L3-L4 layer in front.
- **Compliance certification** — AEGIS supports OWASP Top 10 alignment; SOC2/GDPR/HIPAA/PCI require process, contracts, and audit beyond code.

**On the self-hardening loop specifically:**

- The loop **reduces toil and makes coverage compound, but it is not a security audit.**
- A **closed loop shares its own blind spots** — it cannot find a vulnerability class it
  does not model. The battery and corpus only test what we thought to test. External
  pentest and human review remain required before AEGIS protects anything sensitive.
- **"Stronger every day" is bounded** by what the battery and corpus can model. The
  human-review gate on every merge is a **permanent feature, not temporary scaffolding** —
  do not remove it once the loop "seems trustworthy." That is precisely when an
  unsupervised self-rewrite would be most dangerous.

AEGIS reduces risk and enforces safe defaults. It is **not** a guarantee of security.

## Maintenance policy

Security decays without upkeep. To keep AEGIS effective:

- **Patch cadence** — run `pip-audit` weekly (the CI job already does) and on every deploy. Apply security patches to pinned deps (`requirements.txt`) within **7 days** for high/critical CVEs, **30 days** otherwise. Re-pin and re-run the full suite after each bump.
- **New CVE response** — when `pip-audit` flags a wrapped library (argon2-cffi, PyJWT, cryptography, redis, bleach, Django): assess exploitability against your usage, bump to the fixed version, run `pytest` + `bandit`, and redeploy. Treat a CVE in a crypto/auth dependency as high priority regardless of CVSS.
- **Crypto agility** — ciphertext is versioned (`aegis1:`) so algorithms can be rotated. Rotate `AEGIS_SECRET_KEY` and `AEGIS_FIELD_ENCRYPTION_KEY` on a schedule and on any suspected exposure; plan for envelope re-encryption when rotating field keys.
- **What decays without upkeep** — TLS config and cipher suites, CSP/permissions policy as the app adds origins, the RBAC policy as roles change, the trusted-proxy list as infra changes, and the dependency set as CVEs accumulate. Review these quarterly.
- **Re-test after changes** — never disable a module or relax a default in production without re-running the adversarial + fail-closed suites and re-reading the threat model.
- **Re-audit** — commission a fresh external pentest after any significant change to the auth, authz, or crypto paths, and at least annually.
