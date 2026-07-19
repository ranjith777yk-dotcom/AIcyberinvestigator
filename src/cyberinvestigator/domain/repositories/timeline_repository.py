"""Persistence contract for timeline events."""

from __future__ import annotations

from typing import Protocol

from cyberinvestigator.infrastructure.database.models import TimelineEvent


class TimelineRepository(Protocol):
    """Repository boundary for recording timeline events."""

    def add(self, event: TimelineEvent) -> None: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...
