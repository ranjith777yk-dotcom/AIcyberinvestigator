"""Persistence contract for case-linked evidence records."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from cyberinvestigator.infrastructure.database.models import Evidence


class EvidenceRepository(Protocol):
    """Repository boundary required by the evidence-management service."""

    def add(self, evidence: Evidence) -> None:
        """Stage a newly registered evidence record for persistence."""
        ...

    def get_by_id(self, evidence_id: UUID, *, include_deleted: bool = False) -> Evidence | None:
        """Return evidence by identifier, hiding soft-deleted records by default."""
        ...

    def get_by_case_and_number(self, case_id: UUID, evidence_number: str) -> Evidence | None:
        """Return active evidence by its case-scoped evidence number."""
        ...

    def list_for_case(self, case_id: UUID) -> list[Evidence]:
        """Return active evidence records for one case."""
        ...

    def commit(self) -> None:
        """Commit staged evidence changes."""
        ...

    def rollback(self) -> None:
        """Rollback the current evidence transaction."""
        ...
