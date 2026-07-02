# AEGIS on FastAPI — "plug-and-play" proven on a second framework

This is the payoff for AEGIS's core claim (Requirement B): *the framework-agnostic engine
holds all the security logic; a new stack is one new thin adapter, zero core changes.*

The **same** engine + 13 modules that protect the Django demo protect this FastAPI app —
through [`aegis/adapters/fastapi_adapter.py`](../../aegis/adapters/fastapi_adapter.py)
(~120 lines) and **nothing else**. Diff [`app.py`](app.py) against the Django
[`secure_app.py`](../redteam-demo/secure_app.py): different framework, identical defenses.

```bash
pip install -e ".[fastapi]"
python examples/fastapi-demo/app.py          # http://127.0.0.1:8009
```

## Same attacks, same outcomes (different framework)
| Attack | Result | AEGIS control (unchanged core) |
|--------|--------|--------------------------------|
| Forged `alg:none` token | **401** | AuthN (middleware) |
| Broken access control (user → admin) | **403** | AuthZ via `Depends(require_permission(...))` |
| Mass assignment (`role=admin`) | **422** | Pydantic `extra="forbid"` (framework-native) |
| SSRF → internal address | **400** | `engine.check_egress()` |
| Missing security headers | **present** | Headers module |
| Brute-force / flood / honeypot | blocked | Rate-limit / deception |

## Why it's *idiomatic*, not a port
The adapter respects how FastAPI is meant to be written — which is the honest, senior way
to prove framework-agnosticism (a copy-paste of the Django decorators would be a code
smell):

- **Perimeter controls run in ASGI middleware.** The sync core is bridged onto the event
  loop with `run_in_threadpool` — the correct way to call blocking security logic (argon2,
  crypto) from async code without stalling the loop.
- **Authorization is a dependency** (`Depends(require_permission("users:read"))`) — the
  FastAPI-native way to declare a per-route requirement — reusing the same AuthZ module.
- **Bodies are validated by Pydantic** (`extra="forbid"`), so the adapter never has to
  consume the request stream. AEGIS composes *with* the framework's strengths.

## The one honest caveat
AEGIS's core is synchronous by design (it wraps sync, audited primitives). Under an async
framework it runs in a worker thread per request — correct and safe, with a small
per-request thread-hop cost. For extreme throughput you'd profile it; for the vast majority
of apps it's a non-issue, and it keeps the security logic identical across every adapter.
