"""Timeline DTOs for recording investigation chronology."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True, slots=True, kw_only=True)
class TimelineDTO:
    """A timeline event record returned by TimelineService.

    This DTO is intentionally persistence-oriented (matches TimelineEvent fields)
    because timeline events are append-only and primarily rendered in the UI.
    """

    id: UUID
    case_id: UUID
    evidence_id: UUID | None
    artifact_id: UUID | None
    occurred_at: datetime
    event_type: str
    summary: str
    details: str | None
