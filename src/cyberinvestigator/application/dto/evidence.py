"""Structured DTOs for the evidence-management application service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import BinaryIO
from uuid import UUID


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceAddRequest:
    """Input required to register one uploaded evidence file for a case."""

    case_id: UUID
    evidence_number: str
    filename: str
    content: BinaryIO
    media_type: str | None = None
    source_description: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceDTO:
    """Framework-neutral evidence record returned consistently by the service."""

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
