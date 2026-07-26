"""Composition boundary for the case-management capability."""

from __future__ import annotations

import logging
from uuid import UUID

from sqlalchemy.orm import Session

from cyberinvestigator.application.services import CaseManagementService
from cyberinvestigator.infrastructure.repositories import SQLAlchemyCaseRepository


class CaseFeature:
    """Build case use cases from request-scoped persistence dependencies."""

    def service(
        self,
        session: Session,
        logger: logging.Logger,
        organization_id: UUID | None = None,
    ) -> CaseManagementService:
        return CaseManagementService(SQLAlchemyCaseRepository(session, organization_id), logger)
