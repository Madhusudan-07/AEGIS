# AEGIS Live Security Dashboard

Watch attacks get blocked **in real time**. One command boots an AEGIS-protected app plus
a live observability plane; click **▶ Run red-team** and the browser fires 8 real attacks
at the server — each one bounces off AEGIS and streams into the feed as it happens.

```bash
pip install -e ".[django]"
python examples/dashboard/run_dashboard.py     # opens http://127.0.0.1:8008/_aegis/
```

## What you see
- **Live event feed** — every security event over Server-Sent Events: denials, honeypot
  traps, auth failures, lockouts, anomaly alerts — the moment they occur.
- **Counters** — events, blocked requests, honeypot traps, alerts, auth failures.
- **Audit chain status** — live verification that the hash-chained audit trail is intact
  (tamper-evident), with the entry count.
- **▶ Run red-team** — the browser *is* the attacker: forged `alg:none` token, broken
  access control, mass-assignment, SSRF-to-internal, brute-force, request flood, and a
  scanner probing `/.env`. Watch them all get blocked and logged.

## How it works (the architecture)
The key line is in `server.py`:

```python
STREAM = build_event_stream(config)          # in-memory (dev) OR Redis (multi-instance)
audit_sink = fan_out(STREAM.publish, durable_sink)   # live feed AND durable storage
aegis.secure(config, policy=POLICY, audit_sink=audit_sink)
```

**No new plumbing.** Every security event already flows through the audit log's `sink`
callback (designed in Phase 0); pointing that sink at an `EventStream` makes the whole
system observable with **zero changes to the audit chain**. The `EventStream`
(`aegis/core/events.py`) mirrors the exact in-memory-now / Redis-later shape of AEGIS's
counter stores — and `build_event_stream(config)` picks the transport just like
`build_store`: a `RedisEventStream` (Redis Streams `XADD`/`XREAD`) when `redis_url` is set,
so **many app instances share one live feed with zero consumer changes**, else the
in-memory ring for dev. `fan_out` then feeds that live feed **and** a durable audit sink
(`FileAuditSink` JSONL or `PostgresAuditSink`) from the one seam, so the hash-chained trail
survives restarts.

The dashboard's own routes live under an **exempt** prefix (`/_aegis/`), so firing the
red team — including the honeypot that blocklists the local IP — never takes the dashboard
itself offline. (That's the `exempt_path_prefixes` config: monitoring/health endpoints are
never authed, rate-limited, or blocked.)

## Run with Docker (one command: app + Redis + Postgres)

```bash
docker compose up      # -> http://localhost:8008/_aegis/
```

Boots a complete production-shaped stack:
- **real Redis** — the hot-path stores (rate-limit, lockout, deception blocklist) **and**
  the live `RedisEventStream` run on Redis, not the in-memory dev fallback
  (`AEGIS_REDIS_URL`), exercising AEGIS's multi-instance path exactly as production would;
- **real Postgres** — the hash-chained audit trail is written durably via `PostgresAuditSink`
  (`AEGIS_AUDIT_DSN`) to a persistent volume, so it **survives restarts**;
- the dashboard image runs as a **non-root** user and binds `0.0.0.0` only inside the container.

(Locally, without Docker, the same code falls back to the in-memory stream; set
`AEGIS_AUDIT_FILE=./audit.jsonl` to get a durable JSONL trail with zero dependencies.)

## ⚠️ Honest scope
- The dashboard is a **dev/operator observability view** — it has no auth of its own and
  binds to localhost. In production you'd put it behind your own auth. (It already reads
  from the shared Redis stream under Docker, so it works across instances.)
- It shows *what AEGIS did* (blocks, alerts, the audit chain). It is **not a SIEM** and does
  not correlate across services — but history is now durable (Postgres / JSONL via the
  `audit_sink`), not just the in-memory ring. Point a real SIEM at that trail for
  cross-service correlation.
