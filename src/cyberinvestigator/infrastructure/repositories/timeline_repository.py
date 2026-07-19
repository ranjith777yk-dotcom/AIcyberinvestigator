"""SQLAlchemy repository implementation for timeline events."""

from __future__ import annotations

from sqlalchemy.orm import Session

from cyberinvestigator.infrastructure.database.models import TimelineEvent


class SQLAlchemyTimelineRepository:
    """Persist TimelineEvent models."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, event: TimelineEvent) -> None:
        self._session.add(event)

    def commit(self) -> None:
        self._session.commit()

    def rollback(self) -> None:
        self._session.rollback()
