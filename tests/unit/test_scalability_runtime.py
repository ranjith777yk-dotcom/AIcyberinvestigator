from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from cyberinvestigator.infrastructure.cache import SecureTTLCache
from cyberinvestigator.infrastructure.jobs import InProcessJobDispatcher


def test_secure_cache_is_bounded_scoped_and_returns_copies() -> None:
    cache = SecureTTLCache(max_entries=2)
    source = {"records": ["case-a"]}
    cache.set("user:one", source, ttl_seconds=30)
    source["records"].append("mutated")
    cached = cache.get("user:one")

    assert cached == {"records": ["case-a"]}
    cached["records"].append("local-change")
    assert cache.get("user:one") == {"records": ["case-a"]}

    cache.set("user:two", {}, ttl_seconds=30)
    cache.set("user:three", {}, ttl_seconds=30)
    snapshot = cache.snapshot()
    assert snapshot["entries"] == 2
    assert snapshot["evictions"] == 1
    assert snapshot["shared_across_replicas"] is False
    assert snapshot["sensitive_values_persisted"] is False


def test_dispatcher_reports_real_queue_and_completion_statistics() -> None:
    release = threading.Event()
    started = threading.Event()
    with ThreadPoolExecutor(max_workers=1) as executor:
        dispatcher = InProcessJobDispatcher(executor, worker_capacity=1)

        def task() -> None:
            started.set()
            release.wait(timeout=3)

        dispatcher.submit(task)
        assert started.wait(timeout=3)
        running = dispatcher.snapshot()
        assert running["running"] == 1
        assert running["available_workers"] == 0
        release.set()
    completed = dispatcher.snapshot()
    assert completed["completed_since_start"] == 1
    assert completed["durable"] is False
