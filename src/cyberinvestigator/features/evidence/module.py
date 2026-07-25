"""Composition boundary for evidence registration and custody."""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from cyberinvestigator.application.ports.evidence_storage import EvidenceStorage
from cyberinvestigator.application.services import EvidenceService
from cyberinvestigator.infrastructure.evidence_storage import EvidenceFileLocator
from cyberinvestigator.infrastructure.repositories import SQLAlchemyCaseRepository, SQLAlchemyEvidenceRepository


class EvidenceFeature:
    """Build evidence use cases around one configured storage adapter."""

    def __init__(self, storage: EvidenceStorage, locator: EvidenceFileLocator) -> None:
        self._storage = storage
        self._locator = locator

    def service(self, session: Session, logger: logging.Logger) -> EvidenceService:
        return EvidenceService(
            SQLAlchemyCaseRepository(session),
            SQLAlchemyEvidenceRepository(session),
            self._storage,
            logger,
        )

    def resolve_path(self, storage_path: str):
        """Resolve evidence bytes through the approved custody roots."""
        return self._locator.resolve(storage_path)
