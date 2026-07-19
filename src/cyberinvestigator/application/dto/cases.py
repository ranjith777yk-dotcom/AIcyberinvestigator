"""Structured DTOs for the case-management application service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Final
from uuid import UUID


class _Unset:
    """Sentinel type used to distinguish an omitted update field from a null value."""


UNSET: Final = _Unset()
"""Sentinel value representing a field omitted from a partial update request."""


@dataclass(frozen=True, slots=True, kw_only=True)
class CaseCreateRequest:
    """Validated-input candidate for creating one investigation case."""

    case_number: str
    title: str
    description: str | None = None
    severity: str = "medium"


@dataclass(frozen=True, slots=True, kw_only=True)
class CaseUpdateRequest:
    """Partial case information update with explicit omitted-field semantics."""

    title: str | _Unset = UNSET
    description: str | None | _Unset = UNSET
    severity: str | _Unset = UNSET


@dataclass(frozen=True, slots=True, kw_only=True)
class CaseDTO:
    """Consistent, framework-neutral representation of an investigation case."""

    id: UUID
    case_number: str
    title: str
    description: str | None
    severity: str
    opened_at: datetime
    closed_at: datetime | None
    archived_at: datetime | None
    deleted_at: datetime | None
