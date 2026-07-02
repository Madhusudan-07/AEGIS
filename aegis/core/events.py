"""Live event stream — the observability seam for security events.

ASVS V7 (logging & monitoring) · spec principles 6 (no silent failures) + 10 (auditability).

Every security-relevant event already passes through ``AuditLog.record`` -> its ``sink``
callback. Point that sink at :meth:`EventStream.publish` and every deny, alert, honeypot
hit, and auth failure becomes observable live — with **zero changes to the audit chain**.
(The sink seam, designed in Phase 0, is exactly the right abstraction; this just consumes it.)

Threading model: ``publish`` is called from request threads; each dashboard connection
``subscribe``s its own bounded queue and drains it. Same in-memory-now / Redis-later shape
as :mod:`aegis.core.stores` — a ``RedisEventStream`` would swap the transport for
multi-instance without touching consumers.
"""
from __future__ import annotations

import collections
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
