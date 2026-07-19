"""Standard-library request/response schemas for API v1."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID


@dataclass(frozen=True, slots=True)
class ErrorResponse:
    error: dict[str, Any]


@dataclass(frozen=True, slots=True)
class CaseCreateRequest:
    case_number: str
    title: str
    description: str | None = None
    severity: str = "medium"


@dataclass(frozen=True, slots=True)
class CaseUpdateRequest:
    title: str | None = None
    description: str | None = None
    severity: str | None = None


@dataclass(frozen=True, slots=True)
class CaseDTO:
    id: UUID
    case_number: str
    title: str
    description: str | None
    severity: str
    opened_at: datetime
    closed_at: datetime | None
    archived_at: datetime | None
    deleted_at: datetime | None


@dataclass(frozen=True, slots=True)
class EvidenceUploadRequest:
    case_id: UUID
    evidence_number: str
    filename: str
    media_type: str | None = None
    source_description: str | None = None


@dataclass(frozen=True, slots=True)
class EvidenceDTO:
    id: UUID
    case_id: UUID
    evidence_number: str
    original_filename: str
    storage_path: str
    media_type: str | None
    size_bytes: int
    sha256: str
    source_description: str | None
    acquired_at: datetime
    deleted_at: datetime | None


@dataclass(frozen=True, slots=True)
class TimelineDTO:
    id: UUID
    case_id: UUID
    evidence_id: UUID | None
    artifact_id: UUID | None
    occurred_at: datetime
    event_type: str
    summary: str
    details: str | None


@dataclass(frozen=True, slots=True)
class TimelineCreateRequest:
    case_id: UUID
    event_type: str
    summary: str
    evidence_id: UUID | None = None
    artifact_id: UUID | None = None
    details: str | None = None
    occurred_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class AIDStatusResponse:
    available: bool
    enabled: bool
    provider: str
    message: str
