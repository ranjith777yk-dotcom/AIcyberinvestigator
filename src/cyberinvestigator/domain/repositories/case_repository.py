"""Persistence contract for investigation cases."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from cyberinvestigator.infrastructure.database.models import Case


class CaseRepository(Protocol):
    """Repository boundary required by the case-management service."""

    def add(self, case: Case) -> None:
        """Stage a new case for persistence."""
        ...

    def get_by_id(self, case_id: UUID, *, include_deleted: bool = False) -> Case | None:
        """Return one case by identifier, optionally including soft-deleted records."""
        ...

    def get_by_case_number(self, case_number: str) -> Case | None:
        """Return an active case by its unique case number."""
        ...

    def list_all(self, *, include_archived: bool = False) -> list[Case]:
        """Return active cases, optionally including archived records."""
        ...

    def commit(self) -> None:
        """Commit all staged case persistence changes."""
        ...

    def rollback(self) -> None:
        """Rollback the current persistence transaction."""
        ...
