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
aegis.secure(config, policy=POLICY, audit_sink=STREAM.publish)
```

**No new plumbing.** Every security event already flows through the audit log's `sink`
callback (designed in Phase 0); pointing that sink at an `EventStream` makes the whole
system observable with **zero changes to the audit chain**. The `EventStream`
(`aegis/core/events.py`) mirrors the exact in-memory-now / Redis-later shape of AEGIS's
counter stores — swap in a `RedisEventStream` and the dashboard works across many app
instances, no consumer changes.

The dashboard's own routes live under an **exempt** prefix (`/_aegis/`), so firing the
red team — including the honeypot that blocklists the local IP — never takes the dashboard
itself offline. (That's the `exempt_path_prefixes` config: monitoring/health endpoints are
never authed, rate-limited, or blocked.)

## ⚠️ Honest scope
- The dashboard is a **dev/operator observability view** — it has no auth of its own and
  binds to localhost. In production you'd put it behind your own auth and read from the
  Redis stream, not the in-process one.
- It shows *what AEGIS did* (blocks, alerts, the audit chain). It is not a SIEM and does
  not correlate across services or retain history beyond the in-memory ring buffer —
  wire the `audit_sink` to durable storage (Postgres) for that.
