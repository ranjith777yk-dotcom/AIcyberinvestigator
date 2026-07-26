"""Non-durable background job adapter for the current single-process runtime."""

from __future__ import annotations

import threading
import time
from concurrent.futures import Executor

from cyberinvestigator.application.ports.background_jobs import JobCallable


class InProcessJobDispatcher:
    """Submit work to an injected executor.

    This adapter preserves the existing behavior. It is intentionally marked
    non-durable: process restarts lose queued work and it is not an evidence
    isolation boundary.
    """

    def __init__(self, executor: Executor, *, worker_capacity: int = 1) -> None:
        self._executor = executor
        self.worker_capacity = worker_capacity
        self.started_at = time.time()
        self._queued = 0
        self._running = 0
        self._completed = 0
        self._failed = 0
        self._lock = threading.RLock()

    def submit(self, task: JobCallable) -> None:
        with self._lock:
            self._queued += 1

        def tracked() -> None:
            with self._lock:
                self._queued -= 1
                self._running += 1
            try:
                task()
            except Exception:
                with self._lock:
                    self._failed += 1
                raise
            else:
                with self._lock:
                    self._completed += 1
            finally:
                with self._lock:
                    self._running -= 1

        self._executor.submit(tracked)

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "provider": "in_process_thread_pool",
                "durable": False,
                "shared_across_replicas": False,
                "worker_capacity": self.worker_capacity,
                "queued": self._queued,
                "running": self._running,
                "completed_since_start": self._completed,
                "failed_since_start": self._failed,
                "available_workers": max(0, self.worker_capacity - self._running),
                "uptime_seconds": round(time.time() - self.started_at, 3),
            }
