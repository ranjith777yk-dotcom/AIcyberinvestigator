"""Bounded process-local cache with explicit scope and operational statistics."""

from __future__ import annotations

import copy
import threading
import time
from collections import OrderedDict


class SecureTTLCache:
    """Keep scoped response documents in memory with TTL and size bounds."""

    def __init__(self, *, max_entries: int = 256) -> None:
        self.max_entries = max_entries
        self._items: OrderedDict[str, tuple[float, object]] = OrderedDict()
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._lock = threading.RLock()

    def get(self, key: str) -> object | None:
        now = time.monotonic()
        with self._lock:
            item = self._items.get(key)
            if item is None:
                self._misses += 1
                return None
            expires_at, value = item
            if expires_at <= now:
                self._items.pop(key, None)
                self._misses += 1
                self._evictions += 1
                return None
            self._items.move_to_end(key)
            self._hits += 1
            return copy.deepcopy(value)

    def set(self, key: str, value: object, *, ttl_seconds: int) -> None:
        with self._lock:
            self._items[key] = (time.monotonic() + ttl_seconds, copy.deepcopy(value))
            self._items.move_to_end(key)
            while len(self._items) > self.max_entries:
                self._items.popitem(last=False)
                self._evictions += 1

    def invalidate(self, prefix: str = "") -> int:
        with self._lock:
            keys = [key for key in self._items if key.startswith(prefix)]
            for key in keys:
                self._items.pop(key, None)
            return len(keys)

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            requests = self._hits + self._misses
            return {
                "provider": "process_memory",
                "scope": "current_process",
                "shared_across_replicas": False,
                "entries": len(self._items),
                "max_entries": self.max_entries,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": round(self._hits / requests, 6) if requests else None,
                "evictions": self._evictions,
                "sensitive_values_persisted": False,
            }
