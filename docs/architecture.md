# AEGIS Architecture

Diagrams-as-code (Mermaid) — they render on GitHub, live next to the code, and diff in
review. Five views, each accurate to the current source: **system context**, **component**,
the **request pipeline**, **trust boundaries**, and the **self-hardening loop**.

---

## 1. System context

Where AEGIS sits: at the HTTP perimeter, in front of your app, backed by Redis for hot-path
state and developer-configured sinks for the audit trail and alerts. It never phones home —
egress goes only to sinks you configure (Principle 7).

```mermaid
flowchart LR
    attacker(["Attacker / Internet"]):::bad
    user(["Legitimate user"]):::ext
    aegis["AEGIS<br/>security layer"]:::aegis
    app["Your app<br/>Django / FastAPI / …"]:::app
    redis[("Redis<br/>rate-limit · lockout<br/>deception blocklist")]:::store
    audit[("Durable audit sink<br/>Postgres / file")]:::store
    alerts[/"Alert sinks<br/>developer-configured only"/]:::sink

    attacker -->|HTTPS| aegis
    user -->|HTTPS| aegis
    aegis -->|allowed requests| app
    aegis -->|hot-path state| redis
    aegis -->|hash-chained events| audit
    aegis -->|anomaly alerts| alerts

    classDef bad fill:#3a1519,stroke:#ff5c6c,color:#ffd7db;
    classDef ext fill:#12202f,stroke:#5aa9ff,color:#dbeeff;
    classDef aegis fill:#10233b,stroke:#4aa8ff,color:#dbeeff;
    classDef app fill:#14231a,stroke:#3ecf8e,color:#d7f5e6;
    classDef store fill:#1a1526,stroke:#b58cff,color:#eadcff;
    classDef sink fill:#241d10,stroke:#ffb454,color:#ffe6c2;
```

---

## 2. Component — one core, thin adapters

The core claim (Requirement B): **all** security logic lives in a framework-agnostic core;
each framework needs only a thin adapter that builds a neutral `RequestContext`. A new
stack = one new adapter, **zero core changes** (Django, FastAPI, and Generic all feed the
same engine).

```mermaid
flowchart TB
    subgraph adapters["Adapters — the ONLY framework-specific code (~120 lines each)"]
      dj["Django<br/>middleware + decorators"]
      fa["FastAPI<br/>ASGI middleware + Depends"]
      gen["Generic<br/>WSGI / callable"]
    end
    ctx["RequestContext / ResponseContext<br/>(the neutral seam)"]:::seam
    engine{{"Engine — orchestration + fail-closed boot self-check"}}:::eng
    modules["12 toggleable modules (pipeline order):<br/>Secrets · Headers/CORS · Deception · RateLimit ·<br/>AuthN · AuthZ · Validation · Session/CSRF ·<br/>Anomaly · Encryption · Audit · SafeErrors"]:::mod
    services["Core services:<br/>Crypto (argon2 · PyJWT · AES-GCM) · Policy (RBAC) ·<br/>Stores (Redis / in-memory) · EventStream · SSRF guard"]:::svc

    dj --> ctx
    fa --> ctx
    gen --> ctx
    ctx --> engine
    engine --> modules
    modules --> services

    classDef seam fill:#10233b,stroke:#4aa8ff,color:#dbeeff;
    classDef eng fill:#132a1f,stroke:#3ecf8e,color:#d7f5e6;
    classDef mod fill:#151d29,stroke:#4a90d9,color:#dbeeff;
    classDef svc fill:#1a1526,stroke:#b58cff,color:#eadcff;
```

---

## 3. Request pipeline (fail-closed gauntlet)

Every request runs the ordered modules; the first violation **denies** (fail-closed). DoS
guards run before expensive auth; the response is hardened on the way out.

```mermaid
flowchart LR
    req(["Request"]) --> H["Headers<br/>resolve trusted IP"]
    H --> D{"Deception<br/>honeypot / blocklist"}
    D -->|trapped| X1["Deny 404"]:::deny
    D --> R{"RateLimit<br/>per-IP"}
    R -->|over limit| X2["Deny 429"]:::deny
    R --> AN{"AuthN<br/>verify JWT"}
    AN -->|forged / expired| X3["Deny 401"]:::deny
    AN --> AZ{"AuthZ<br/>deny-by-default"}
    AZ -->|missing permission| X4["Deny 403"]:::deny
    AZ --> V{"Validation"}
    V -->|bad input| X5["Deny 400"]:::deny
    V --> app["App handler"]:::app
    app --> resp(["Response<br/>+ strict security headers"])

    classDef deny fill:#3a1519,stroke:#ff5c6c,color:#ffd7db;
    classDef app fill:#14231a,stroke:#3ecf8e,color:#d7f5e6;
```

*Store unreachable (Redis down) while a limit/lockout check is needed → **deny**, not
allow-through. Missing secret / wildcard CORS / TLS-not-expected in prod → **refuse to
boot**.*

---

## 4. Trust boundaries

The threat model's boundaries (TB1–TB4). Everything crossing from the internet is
untrusted; AEGIS is the zero-trust perimeter; secrets are loaded but never logged.

```mermaid
flowchart TB
    subgraph UNTRUSTED["UNTRUSTED — TB1 (internet)"]
      net["body · query · headers · cookies · X-Forwarded-*"]:::bad
    end
    subgraph PERIM["AEGIS perimeter — authenticate + authorize EVERY request"]
      pipe["AuthN · AuthZ · Validation · RateLimit · Deception · SafeErrors"]:::aegis
    end
    subgraph TRUSTED["TRUSTED — application"]
      app["App handlers · business logic"]:::app
    end
    subgraph BACKING["TB2 / TB3 — datastores & secrets"]
      redis[("Redis")]:::store
      secrets[/"Secrets: env / KMS only<br/>boot-refuse if missing · redacted from all logs"/]:::sink
    end

    net -->|zero-trust boundary| pipe
    pipe -->|only vetted requests| app
    app --> redis
    pipe -. loads, never logs .-> secrets

    classDef bad fill:#3a1519,stroke:#ff5c6c,color:#ffd7db;
    classDef aegis fill:#10233b,stroke:#4aa8ff,color:#dbeeff;
    classDef app fill:#14231a,stroke:#3ecf8e,color:#d7f5e6;
    classDef store fill:#1a1526,stroke:#b58cff,color:#eadcff;
    classDef sink fill:#241d10,stroke:#ffb454,color:#ffe6c2;
```

---

## 5. The self-hardening loop

How AEGIS gets *monotonically* stronger — safely. The agent **proposes**; a human
**approves**; the ratchet guard guarantees coverage can only grow. The agent can never
merge or touch `main`.

```mermaid
flowchart LR
    daily["Daily battery<br/>pip-audit · bandit · gitleaks<br/>adversarial corpus · fuzz · DAST"]:::gate
    daily -->|finding| agent["AI triage agent<br/>(propose-only)"]:::agent
    agent -->|regression test FIRST| corpus[("Append-only<br/>regression corpus")]:::store
    agent -->|PR to security/auto/*| pr["Pull request"]:::pr
    guard{{"Ratchet guard<br/>coverage can only grow"}}:::gate --> pr
    pr -->|required checks + review| human((("Human<br/>merge"))):::human
    human --> main[("main")]:::store
    main --> daily
    agent -.->|never merges, never touches main| pr

    classDef gate fill:#132a1f,stroke:#3ecf8e,color:#d7f5e6;
    classDef agent fill:#10233b,stroke:#4aa8ff,color:#dbeeff;
    classDef store fill:#1a1526,stroke:#b58cff,color:#eadcff;
    classDef pr fill:#151d29,stroke:#4a90d9,color:#dbeeff;
    classDef human fill:#241d10,stroke:#ffb454,color:#ffe6c2;
```

---

*These diagrams trace directly to the code: the module order is `aegis/core/engine.py`'s
`_MODULE_ORDER`; the adapters are `aegis/adapters/`; the loop is `.github/workflows/` +
`security/`. See [THREAT_MODEL.md](../THREAT_MODEL.md) for the boundaries and STRIDE table
they summarize.*
