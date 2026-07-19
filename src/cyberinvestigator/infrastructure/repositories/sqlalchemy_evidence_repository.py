"""SQLAlchemy repository implementation for evidence records."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberinvestigator.infrastructure.database.models import Evidence


class SQLAlchemyEvidenceRepository:
    """Repository adapter that persists evidence through an injected SQLAlchemy session."""

    def __init__(self, session: Session) -> None:
        """Create a repository bound to one caller-owned session."""
        self._session = session

    def add(self, evidence: Evidence) -> None:
        """Stage a new evidence record for persistence."""
        self._session.add(evidence)

    def get_by_id(self, evidence_id: UUID, *, include_deleted: bool = False) -> Evidence | None:
        """Return one evidence record by identifier."""
        statement = select(Evidence).where(Evidence.id == evidence_id)
        if not include_deleted:
            statement = statement.where(Evidence.deleted_at.is_(None))
        return self._session.scalar(statement)

    def get_by_case_and_number(self, case_id: UUID, evidence_number: str) -> Evidence | None:
        """Return active evidence by its unique number within a case."""
        statement = select(Evidence).where(
            Evidence.case_id == case_id,
            Evidence.evidence_number == evidence_number,
            Evidence.deleted_at.is_(None),
        )
        return self._session.scalar(statement)

    def list_for_case(self, case_id: UUID) -> list[Evidence]:
        """List active evidence records for one case by acquisition time."""
        statement = (
            select(Evidence)
            .where(Evidence.case_id == case_id, Evidence.deleted_at.is_(None))
            .order_by(Evidence.acquired_at.desc())
        )
        return list(self._session.scalars(statement))

    def commit(self) -> None:
        """Commit the session transaction."""
        self._session.commit()

    def rollback(self) -> None:
        """Rollback the session transaction."""
        self._session.rollback()
