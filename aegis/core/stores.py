"""Pluggable counter/KV stores for rate-limit, lockout, and anomaly windows.

Two implementations behind one interface:

* :class:`InMemoryStore` — single-process, for dev/test/CLI.
* :class:`RedisStore`     — multi-instance production (wraps redis-py).

Fail-closed contract: if a Redis store is **configured but unreachable**, operations
raise :class:`StoreUnavailable`; callers (rate-limit, lockout) then DENY rather than
allow-through when ``config.fail_closed_on_store_error`` is set (ASVS V1.5 / spec §10).
"""
from __future__ import annotations

import threading
import time
from typing import Protocol

from .exceptions import AegisError


class StoreUnavailable(AegisError):
    """The backing store could not be reached."""


class CounterStore(Protocol):
    def incr(self, key: str, ttl: int) -> int: ...
    def get_int(self, key: str) -> int: ...
    def set(self, key: str, value: str, ttl: int) -> None: ...
    def get(self, key: str) -> str | None: ...
    def ttl(self, key: str) -> int: ...


class InMemoryStore:
    """Thread-safe in-memory store with TTL. NOT shared across processes."""

    def __init__(self) -> None:
        self._data: dict[str, tuple[str, float]] = {}  # key -> (value, expires_at)
        self._lock = threading.Lock()

    def _purge(self, now: float) -> None:
        expired = [k for k, (_, exp) in self._data.items() if exp and exp <= now]
        for k in expired:
            self._data.pop(k, None)

    def incr(self, key: str, ttl: int) -> int:
        now = time.time()
        with self._lock:
            self._purge(now)
            val, exp = self._data.get(key, ("0", now + ttl))
            new = int(val) + 1
            # keep existing window expiry; only set on first hit
            self._data[key] = (str(new), exp if key in self._data else now + ttl)
            return new

    def get_int(self, key: str) -> int:
        v = self.get(key)
        return int(v) if v is not None else 0

    def set(self, key: str, value: str, ttl: int) -> None:
        with self._lock:
            self._data[key] = (value, time.time() + ttl)

    def get(self, key: str) -> str | None:
        now = time.time()
        with self._lock:
            self._purge(now)
            item = self._data.get(key)
            return item[0] if item else None

    def ttl(self, key: str) -> int:
        with self._lock:
            item = self._data.get(key)
            if not item:
                return 0
            return max(0, int(item[1] - time.time()))


class RedisStore:
    """Redis-backed store (wraps redis-py). Raises :class:`StoreUnavailable` on outage."""

    def __init__(self, url: str):
        try:
            import redis  # optional dependency
        except ImportError as exc:  # pragma: no cover
            raise StoreUnavailable("redis package not installed") from exc
        self._redis = redis.Redis.from_url(url, decode_responses=True, socket_timeout=2)

    def _guard(self, fn):
        try:
            return fn()
        except Exception as exc:  # redis.exceptions.* -> uniform fail-closed signal
            raise StoreUnavailable(str(exc)) from exc

    def incr(self, key: str, ttl: int) -> int:
        def op():
            pipe = self._redis.pipeline()
            pipe.incr(key)
            pipe.expire(key, ttl, nx=True)  # only set expiry if not already set
            return pipe.execute()[0]
        return int(self._guard(op))

    def get_int(self, key: str) -> int:
        v = self.get(key)
        return int(v) if v is not None else 0

    def set(self, key: str, value: str, ttl: int) -> None:
        self._guard(lambda: self._redis.set(key, value, ex=ttl))

    def get(self, key: str) -> str | None:
        return self._guard(lambda: self._redis.get(key))

    def ttl(self, key: str) -> int:
        return max(0, int(self._guard(lambda: self._redis.ttl(key)) or 0))


def build_store(config) -> CounterStore:
    """Factory: Redis when ``redis_url`` is set, else in-memory (dev)."""
    if config.redis_url:
        return RedisStore(config.redis_url)
    return InMemoryStore()
