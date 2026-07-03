"""RedisEventStream — the multi-instance transport for the live feed.

Proves the Redis-backed stream is a true drop-in for the in-memory EventStream (same
publish / subscribe / recent / stats surface) using an in-process fake Redis, so no server
is needed in CI. The dashboard's SSE loop is unchanged across both transports.
"""
from __future__ import annotations

import queue
import types

import pytest

fakeredis = pytest.importorskip("fakeredis")

from aegis.core.events import EventStream, RedisEventStream, build_event_stream  # noqa: E402


@pytest.fixture
def stream():
    client = fakeredis.FakeStrictRedis(decode_responses=True)
    return RedisEventStream(client, capacity=100, namespace="test:events")


def test_publish_and_recent_are_oldest_first(stream):
    stream.publish({"event": "deny", "fields": {"n": 1}})
    stream.publish({"event": "deny", "fields": {"n": 2}})
    stream.publish({"event": "alert", "fields": {"n": 3}})
    assert [e["fields"]["n"] for e in stream.recent()] == [1, 2, 3]


def test_stats_counts_by_type(stream):
    stream.publish({"event": "deny", "fields": {}})
    stream.publish({"event": "deny", "fields": {}})
    stream.publish({"event": "authn.fail", "fields": {}})
    s = stream.stats()
    assert s["events"] == 3
    assert s["by_type"] == {"deny": 2, "authn.fail": 1}


def test_publish_never_raises_on_bad_entry(stream):
    stream.publish(["not", "a", "dict"])   # entry.get(...) would raise -> must be swallowed
    stream.publish({"event": "ok", "fields": {}})
    assert stream.stats()["events"] == 1   # only the good one landed


def test_subscribe_delivers_only_new_events(stream):
    stream.publish({"event": "before", "fields": {}})   # published BEFORE subscribe
    sub = stream.subscribe()
    stream.publish({"event": "after", "fields": {"k": 42}})
    got = sub.get(timeout=2)
    assert got["event"] == "after" and got["fields"]["k"] == 42


def test_get_nowait_on_empty_raises_empty(stream):
    sub = stream.subscribe()
    with pytest.raises(queue.Empty):
        sub.get_nowait()


def test_unsubscribe_closes_and_tracks_local_count(stream):
    sub = stream.subscribe()
    assert stream.stats()["subscribers"] == 1
    stream.unsubscribe(sub)
    assert stream.stats()["subscribers"] == 0
    with pytest.raises(queue.Empty):   # a closed subscription yields nothing further
        sub.get_nowait()


def test_recent_respects_limit(stream):
    for i in range(10):
        stream.publish({"event": "e", "fields": {"i": i}})
    tail = stream.recent(3)
    assert [e["fields"]["i"] for e in tail] == [7, 8, 9]


def test_build_event_stream_selects_transport():
    assert isinstance(build_event_stream(types.SimpleNamespace(redis_url="")), EventStream)
    picked = build_event_stream(types.SimpleNamespace(redis_url="redis://localhost:6379/0"))
    assert isinstance(picked, RedisEventStream)   # constructed lazily; no connection yet
