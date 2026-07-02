# AEGIS — Phase 0 Threat Model

> This document is the **gate**: it is produced before any code, and every control
> AEGIS implements traces back to a threat here. Controls with no threat were cut.
> Threats with no control are flagged as **GAPS**, not hidden.

## Resolved PROJECT CONTEXT

| field | value |
|-------|-------|
| language | Python 3.12 |
| framework | Django (DRF-compatible) |
| app_type | web app / REST API |
| existing_auth | none — AEGIS builds AuthN (wraps PyJWT + argon2-cffi) |
| datastore | Postgres (durable: audit, sessions) + Redis (hot path: rate limit, lockout, anomaly) |
| deploy_target | Docker (assumed) |
| data_sensitivity | PII |
| threat_actors | external: script kiddies + financially-motivated criminals |
| asvs_target | **OWASP ASVS L2 (standard)** |
| compliance_targets | OWASP Top 10 (2021) |
| risk_posture | maximum |

## 1. Assets & trust boundaries

**Assets worth protecting**
- A1 User credentials (passwords, tokens, session cookies).
- A2 PII at rest and in transit (the `data_sensitivity` driver).
- A3 Authorization state — who may do what.
- A4 The audit trail itself (integrity / non-repudiation).
- A5 Application secrets & encryption keys.
- A6 Availability of the auth/login path.

**Trust boundaries** (where untrusted meets trusted)
- TB1 Internet → Django (HTTP request boundary). **Everything across TB1 is untrusted**: body, query, headers, cookies, `X-Forwarded-*`.
- TB2 Django app → Postgres / Redis (datastore boundary).
- TB3 App process → secret manager / environment (secret boundary).
- TB4 App → developer-configured log/alert sinks (egress boundary — must never become an exfiltration channel).

## 2. Attacker capabilities (derived from `threat_actors`)

In scope (what they can attempt):
- Send arbitrary HTTP requests, forge any header/cookie/body, replay captured requests.
- Automate at scale: credential stuffing, brute force, scraping, fuzzing.
- Submit injection payloads (SQLi/NoSQLi/command/XSS/SSRF/path traversal).
- Forge or tamper with tokens (incl. `alg:none`, expired, wrong-signature JWTs).
- Probe for misconfiguration (wildcard CORS, missing headers, verbose errors).

Out of scope (explicitly NOT defended here — see README *Limitations*):
- Nation-state / supply-chain implant in a vetted dependency beyond CVE scanning.
- Physical access to the host or datastore.
- Malicious insider with production credentials.
- Compromise of the developer's secret manager itself.

## 3. STRIDE

| # | Threat (STRIDE) | Scenario across a trust boundary | Control(s) → module | ASVS |
|---|-----------------|----------------------------------|---------------------|------|
| S1 | **Spoofing** | Attacker forges a JWT / session to impersonate a user | Vetted JWT verify (PyJWT, explicit `algorithms`, `alg:none` rejected) + argon2id passwords → **AuthN** | V2, V3 |
| S2 | Spoofing | Attacker trusts-on-our-behalf via `X-Forwarded-For` to bypass IP controls | Forwarded headers only honored from a configured trusted-proxy allowlist → **Headers/Context** | V1 |
| T1 | **Tampering** | Mutating request body to change another user's record | Schema validation, reject unknown fields, deny-by-default authz → **Validation + AuthZ** | V4, V5 |
| T2 | Tampering | Editing the audit log to hide activity | Hash-chained append-only entries (tamper-evident) → **Audit** | V7 |
| R1 | **Repudiation** | User denies performing a security-relevant action | Correlation-ID'd, append-only audit of every security event → **Audit** | V7 |
| I1 | **Info disclosure** | Stack trace / version leak in an error response | Generic client errors, full detail only to internal log → **SafeErrors** | V7, V14 |
| I2 | Info disclosure | Secrets / tokens / PII written to logs | Redaction filter on every log + audit record → **Secrets + Audit** | V7 |
| I3 | Info disclosure | PII readable in a dumped database | AES-256-GCM field encryption helper → **Encryption** | V6 |
| I4 | Info disclosure | Cross-origin page reads API response (wildcard CORS) | CORS allowlist, **no wildcard in prod (boot-refused)** + strict CSP → **Headers** | V14 |
| D1 | **DoS** | Credential stuffing / brute force / request flood | Per-IP + per-identity rate limiting, lockout w/ backoff → **RateLimit** | V2, V11 |
| E1 | **Elevation** | Regular user invokes an admin action | Centralized RBAC, **deny-by-default**, deny on policy-engine error → **AuthZ** | V4 |
| E2 | Elevation | Session fixation / privilege kept after role change | Session rotation on privilege change + CSRF on state change → **Session** | V3 |

## 4. Abuse cases (top risks → "attacker does X to achieve Y")

- **AC1 — Credential stuffing:** attacker replays 50k leaked email/password pairs to take over accounts.
  → RateLimit (per-IP + per-identity), lockout w/ exponential backoff, argon2id slows offline cracking, Anomaly alerts on the failure spike.
- **AC2 — Forged-token elevation:** attacker submits a JWT with `alg:none` or a self-signed key to become admin.
  → AuthN rejects unverified/`none`/wrong-alg tokens; AuthZ still independently denies (defense in depth).
- **AC3 — IDOR / mass assignment:** attacker changes `user_id`/`role` in a JSON body to edit another record or self-promote.
  → Validation rejects unknown fields; AuthZ deny-by-default authorizes the specific object/action.
- **AC4 — Misconfig harvest:** attacker scans for wildcard CORS + verbose errors to exfiltrate data cross-origin.
  → Boot self-check refuses to start with wildcard CORS in prod; SafeErrors strips internals; strict CSP/HSTS headers.
- **AC5 — Log scraping:** attacker triggers errors hoping secrets/PII land in logs they can later read.
  → Redaction filter + SafeErrors guarantee no secret/PII/stack-trace reaches client or log sink.

## 5. Defense-in-depth map (each critical asset ≥ 2 independent controls)

| Asset | Control 1 | Control 2 |
|-------|-----------|-----------|
| A1 credentials | argon2id hashing | rate-limit + lockout + anomaly alert |
| A2 PII | field encryption (at rest) | TLS-expected boot gate + redaction (in transit / logs) |
| A3 authz state | RBAC deny-by-default | AuthN identity verification upstream |
| A4 audit trail | hash chain (tamper-evident) | append-only sink + redaction |
| A5 secrets/keys | env/secret-manager only, boot-refuse on missing | redaction from all logs/errors |
| A6 login availability | per-IP rate limit | per-identity lockout w/ backoff |

## 6. Flagged GAPS (threats acknowledged, not silently dropped)

- **G1** AEGIS cannot stop a *valid* authenticated user abusing their own legitimate
  privileges (business-logic abuse). Mitigation is rate-limit + audit + anomaly only.
- **G2** ~~SSRF protection is advisory~~ — **ADDRESSED (v2):** the egress guard
  (`engine.check_egress`, `aegis/core/egress.py`) resolves DNS and blocks
  loopback/private/link-local/metadata targets before any fetch. Residual: call-time
  validation isn't a substitute for a network-layer egress firewall (DNS-rebinding/TOCTOU,
  permissive host networks). Reduced from a gap to a documented limitation.
- **G3** Anomaly detection is heuristic (threshold/velocity), not ML — **ADVANCED (v2):**
  the deception module (`aegis/core/modules/deception.py`) turns scanner recon into a
  high-confidence trap-and-block signal, cheaply removing the noisy majority. Residual: a
  careful low-and-slow attacker who avoids the decoys still isn't caught. Advanced, not
  closed.
- **G4** Generated code carries **no audit or attack history** — see README
  *Limitations & External Audit*. This must be pentested before guarding real data.
