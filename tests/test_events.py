"""EventStream — the live observability seam (Phase 3 dashboard)."""
from __future__ import annotations

import queue

from aegis.core.events import EventStream


def test_publish_and_recent():
    s = EventStream()
    for i in range(3):
        s.publish({"event": "aegis.deny", "fields": {"n": i}})
    r = s.recent()
    assert len(r) == 3 and r[-1]["fields"]["n"] == 2


def test_stats_counts_by_type():
    s = EventStream()
    s.publish({"event": "aegis.deny"})
    s.publish({"event": "aegis.deny"})
    s.publish({"event": "deception.honeypot_hit"})
    st = s.stats()
    assert st["events"] == 3 and st["by_type"]["aegis.deny"] == 2


def test_subscriber_receives_events():
    s = EventStream()
    q = s.subscribe()
    s.publish({"event": "x"})
    assert q.get_nowait()["event"] == "x"


def test_multiple_subscribers_all_receive():
    s = EventStream()
    a, b = s.subscribe(), s.subscribe()
    s.publish({"event": "z"})
    assert a.get_nowait()["event"] == "z" and b.get_nowait()["event"] == "z"


def test_unsubscribe_stops_delivery():
    s = EventStream()
    q = s.subscribe()
    s.unsubscribe(q)
    s.publish({"event": "y"})
    try:
        q.get_nowait()
        raise AssertionError("unsubscribed queue still received an event")
    except queue.Empty:
        pass


def test_ring_buffer_is_bounded():
    s = EventStream(capacity=5)
    for i in range(20):
        s.publish({"event": "e", "fields": {"i": i}})
    r = s.recent(100)
    assert len(r) == 5 and r[0]["fields"]["i"] == 15  # oldest 15 dropped


def test_publish_never_raises_and_drops_bad_entry():
    # Observability must never break the app: a bad entry is swallowed, not stored.
    s = EventStream()
    s.publish(None)               # would AttributeError internally — must not propagate
    s.publish({"event": "ok"})
    st = s.stats()
    assert st["events"] == 1 and all(e is not None for e in s.recent())
