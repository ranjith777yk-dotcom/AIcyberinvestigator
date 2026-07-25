"""Non-durable background job adapter for the current single-process runtime."""

from __future__ import annotations

from concurrent.futures import Executor

from cyberinvestigator.application.ports.background_jobs import JobCallable


class InProcessJobDispatcher:
    """Submit work to an injected executor.

    This adapter preserves the existing behavior. It is intentionally marked
    non-durable: process restarts lose queued work and it is not an evidence
    isolation boundary.
    """

    def __init__(self, executor: Executor) -> None:
        self._executor = executor

    def submit(self, task: JobCallable) -> None:
        self._executor.submit(task)
