"""SQLAlchemy repository implementation for investigation cases."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberinvestigator.infrastructure.database.models import Case


class SQLAlchemyCaseRepository:
    """Repository adapter that persists case models through an injected session."""

    def __init__(self, session: Session) -> None:
        """Create a repository bound to one caller-owned SQLAlchemy session."""
        self._session = session

    def add(self, case: Case) -> None:
        """Stage a newly created case model for persistence."""
        self._session.add(case)

    def get_by_id(self, case_id: UUID, *, include_deleted: bool = False) -> Case | None:
        """Return a case by identifier, hiding soft-deleted cases by default."""
        statement = select(Case).where(Case.id == case_id)
        if not include_deleted:
            statement = statement.where(Case.deleted_at.is_(None))
        return self._session.scalar(statement)

    def get_by_case_number(self, case_number: str) -> Case | None:
        """Return an active case with the supplied case number, if present."""
        statement = select(Case).where(Case.case_number == case_number, Case.deleted_at.is_(None))
        return self._session.scalar(statement)

    def list_all(self, *, include_archived: bool = False) -> list[Case]:
        """List active cases ordered by most recently opened investigation."""
        statement = select(Case).where(Case.deleted_at.is_(None))
        if not include_archived:
            statement = statement.where(Case.archived_at.is_(None))
        statement = statement.order_by(Case.opened_at.desc())
        return list(self._session.scalars(statement))

    def commit(self) -> None:
        """Commit the session transaction."""
        self._session.commit()

    def rollback(self) -> None:
        """Rollback the session transaction."""
        self._session.rollback()
