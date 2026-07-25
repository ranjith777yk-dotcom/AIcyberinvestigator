"""Application boundary for dispatching non-request work."""

from __future__ import annotations

from typing import Callable, Protocol

JobCallable = Callable[[], None]


class BackgroundJobDispatcher(Protocol):
    """Dispatch a callable without coupling use cases to an executor implementation.

    Implementations may be in-process for local development or backed by a
    durable queue in production. Callers must not assume completion, ordering,
    retries, or process affinity.
    """

    def submit(self, task: JobCallable) -> None:
        """Schedule one task for asynchronous execution."""
        ...
