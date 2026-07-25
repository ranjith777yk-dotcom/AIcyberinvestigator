"""Composition boundary for investigation timeline use cases."""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from cyberinvestigator.application.services.timeline_service import TimelineService
from cyberinvestigator.domain.services.timeline_reconstruction import TimelineReconstructionEngine
from cyberinvestigator.infrastructure.repositories.timeline_repository import SQLAlchemyTimelineRepository


class TimelineFeature:
    """Build timeline use cases from request-scoped persistence dependencies."""

    def service(self, session: Session, logger: logging.Logger) -> TimelineService:
        return TimelineService(SQLAlchemyTimelineRepository(session), logger)

    @property
    def reconstruction(self) -> TimelineReconstructionEngine:
        return TimelineReconstructionEngine()
