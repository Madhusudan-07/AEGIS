"""Live event stream — the observability seam for security events.

ASVS V7 (logging & monitoring) · spec principles 6 (no silent failures) + 10 (auditability).

Every security-relevant event already passes through ``AuditLog.record`` -> its ``sink``
callback. Point that sink at :meth:`EventStream.publish` and every deny, alert, honeypot
hit, and auth failure becomes observable live — with **zero changes to the audit chain**.
(The sink seam, designed in Phase 0, is exactly the right abstraction; this just consumes it.)

Threading model: ``publish`` is called from request threads; each dashboard connection
``subscribe``s its own bounded queue and drains it. Same in-memory-now / Redis-later shape
as :mod:`aegis.core.stores`: :class:`RedisEventStream` swaps the transport for a Redis
Stream so many app instances share one live feed — **without touching a single consumer**.
Both expose the identical ``publish / subscribe / unsubscribe / recent / stats`` surface,
and :func:`build_event_stream` picks the right one from config exactly like ``build_store``.
"""
from __future__ import annotations

import collections
import json
import queue
import threading
import time


class EventStream:
    def __init__(self, capacity: int = 500):
        self._ring: collections.deque = collections.deque(maxlen=capacity)
        self._subscribers: list[queue.Queue] = []
        self._counts: collections.Counter = collections.Counter()
        self._lock = threading.Lock()

    def publish(self, entry: dict) -> None:
        """Sink callback: fan an audit entry out to the ring buffer + all subscribers.

        Must never raise into the caller (a failing observer can't break request handling).
        """
        try:
            with self._lock:
                event = entry.get("event", "?")   # raises on a bad entry before we store it
                self._ring.append(entry)
                self._counts[event] += 1
                subscribers = list(self._subscribers)
            for q in subscribers:
                try:
                    q.put_nowait(entry)
                except queue.Full:
                    pass  # slow consumer drops events rather than blocking a request
        except Exception:  # nosec B110 - observability must not break the app
            pass

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=1000)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def recent(self, n: int = 100) -> list[dict]:
        with self._lock:
            return list(self._ring)[-n:]

    def stats(self) -> dict:
        with self._lock:
            return {"events": sum(self._counts.values()), "by_type": dict(self._counts),
                    "subscribers": len(self._subscribers), "ts": time.time()}


class _RedisSubscription:
    """Queue-compatible cursor over a Redis stream.

    Exposes the slice of :class:`queue.Queue` the SSE loop uses — ``get(timeout)`` that
    raises :class:`queue.Empty` when nothing arrives in time — so the dashboard tails a
    shared Redis feed with the *same* code that drains an in-memory queue.
    """

    def __init__(self, client, stream: str, start_id: str):
        self._client = client
        self._stream = stream
        self._last = start_id            # concrete id resolved at subscribe() — never "$"
        self._buf: collections.deque = collections.deque()
        self._closed = False

    def get(self, timeout: float | None = None):
        if self._buf:
            return self._buf.popleft()
        if self._closed:
            raise queue.Empty
        # redis-py block semantics: None = non-blocking, 0 = forever, N = N milliseconds.
        if timeout is None:
            block = 0
        elif timeout <= 0:
            block = None
        else:
            block = int(timeout * 1000)
        try:
            resp = self._client.xread({self._stream: self._last}, count=64, block=block)
        except Exception as exc:  # blocking read cancelled / transport hiccup -> treat as idle
            raise queue.Empty from exc
        if not resp:
            raise queue.Empty
        for _stream, entries in resp:
            for msg_id, fields in entries:
                self._last = msg_id
                raw = fields.get("json")
                if raw is None:
                    continue
                try:
                    self._buf.append(json.loads(raw))
                except (ValueError, TypeError):
                    pass  # a malformed frame can't stall the live feed
        if not self._buf:
            raise queue.Empty
        return self._buf.popleft()

    def get_nowait(self):
        return self.get(timeout=0)

    def close(self) -> None:
        self._closed = True


class RedisEventStream:
    """Multi-instance event stream backed by a Redis Stream (``XADD`` / ``XREAD``).

    Drop-in for :class:`EventStream` — same surface, different transport — so every app
    instance publishes to and tails one shared feed. A capped stream (``MAXLEN``) bounds
    memory the way the in-memory ring's ``maxlen`` does; a counters hash keeps ``stats``
    O(1) instead of scanning history. Like :class:`EventStream`, ``publish`` never raises
    into the caller: a wobbly Redis can slow the dashboard but can never break a request.
    """

    def __init__(self, client, *, capacity: int = 500, namespace: str = "aegis:events"):
        self._client = client
        self._capacity = capacity
        self._stream = namespace
        self._counts_key = f"{namespace}:counts"
        self._lock = threading.Lock()
        self._local_subs = 0

    @classmethod
    def from_url(cls, url: str, **kw) -> "RedisEventStream":
        try:
            import redis  # optional dependency (the `redis` extra)
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("redis package not installed; `pip install aegis-security[redis]`") from exc
        # No small socket_timeout: blocking XREAD is expected on the read path.
        return cls(redis.Redis.from_url(url, decode_responses=True), **kw)

    def publish(self, entry: dict) -> None:
        try:
            event = entry.get("event", "?")   # raises on a bad entry before we touch Redis
            pipe = self._client.pipeline()
            pipe.xadd(self._stream, {"json": json.dumps(entry, default=str)},
                      maxlen=self._capacity, approximate=True)
            pipe.hincrby(self._counts_key, event, 1)
            pipe.execute()
        except Exception:  # nosec B110 - observability must not break the app
            pass

    def subscribe(self) -> _RedisSubscription:
        # Resolve "new events only" to a CONCRETE id now, so a publish that races a slow
        # subscriber is never skipped (unlike a re-resolving "$").
        last = "0"
        try:
            tail = self._client.xrevrange(self._stream, count=1)
            if tail:
                last = tail[0][0]
        except Exception:  # nosec B110 - best-effort tail resolution; "0" (from start) is a safe default
            pass
        with self._lock:
            self._local_subs += 1
        return _RedisSubscription(self._client, self._stream, last)

    def unsubscribe(self, sub: _RedisSubscription) -> None:
        sub.close()
        with self._lock:
            self._local_subs = max(0, self._local_subs - 1)

    def recent(self, n: int = 100) -> list[dict]:
        try:
            rows = self._client.xrevrange(self._stream, count=n)  # newest-first
        except Exception:
            return []
        out = []
        for _id, fields in reversed(rows):  # -> oldest-first, matching the in-memory ring
            raw = fields.get("json")
            if raw is None:
                continue
            try:
                out.append(json.loads(raw))
            except (ValueError, TypeError):
                pass
        return out

    def stats(self) -> dict:
        try:
            counts = {k: int(v) for k, v in (self._client.hgetall(self._counts_key) or {}).items()}
        except Exception:
            counts = {}
        return {"events": sum(counts.values()), "by_type": counts,
                "subscribers": self._local_subs, "ts": time.time()}


def build_event_stream(config):
    """Factory: a Redis-backed stream when ``redis_url`` is set, else in-memory (dev).

    Mirrors :func:`aegis.core.stores.build_store` — the dashboard asks for a stream and
    gets the right transport for its deployment, with no consumer-side changes.
    """
    if getattr(config, "redis_url", ""):
        return RedisEventStream.from_url(config.redis_url)
    return EventStream()
