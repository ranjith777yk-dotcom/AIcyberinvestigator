"""Application service that owns evidence registration and custody metadata."""

from __future__ import annotations

import logging
import re
from typing import Final
from uuid import UUID

from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from cyberinvestigator.application.dto.evidence import EvidenceAddRequest, EvidenceDTO
from cyberinvestigator.application.ports.evidence_storage import EvidenceStorage
from cyberinvestigator.domain.repositories import CaseRepository, EvidenceRepository
from cyberinvestigator.infrastructure.database.base import utc_now
from cyberinvestigator.infrastructure.database.models import Evidence
from cyberinvestigator.shared.exceptions import (
    CaseNotFoundError,
    EvidenceConflictError,
    EvidenceNotFoundError,
    EvidencePersistenceError,
    EvidenceStorageError,
    EvidenceValidationError,
)


class EvidenceService:
    """Coordinate evidence metadata validation, durable storage, and persistence."""

    _EVIDENCE_NUMBER_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

    def __init__(
        self,
        case_repository: CaseRepository,
        evidence_repository: EvidenceRepository,
        storage: EvidenceStorage,
        logger: logging.Logger | None = None,
    ) -> None:
        """Create the service with explicit repository, storage, and logging dependencies."""
        self._case_repository = case_repository
        self._evidence_repository = evidence_repository
        self._storage = storage
        self._logger = logger or logging.getLogger(__name__)

    def add_evidence(self, request: EvidenceAddRequest) -> EvidenceDTO:
        """Store an uploaded file and persist its immutable custody metadata."""
        case = self._case_repository.get_by_id(request.case_id)
        if case is None:
            raise CaseNotFoundError(f"Case {request.case_id} was not found.")
        evidence_number = self._validate_evidence_number(request.evidence_number)
        filename = self._validate_filename(request.filename)
        source_description = self._validate_source_description(request.source_description)
        if self._evidence_repository.get_by_case_and_number(case.id, evidence_number) is not None:
            raise EvidenceConflictError(f"Evidence number {evidence_number!r} already exists in this case.")

        stored = self._storage.store(
            case_id=case.id,
            filename=filename,
            content=request.content,
            media_type=self._validate_media_type(request.media_type),
        )
        evidence = Evidence(
            case_id=case.id,
            evidence_number=evidence_number,
            original_filename=filename,
            storage_path=stored.storage_path,
            media_type=stored.media_type,
            size_bytes=stored.size_bytes,
            sha256=stored.sha256,
            source_description=source_description,
        )
        self._evidence_repository.add(evidence)
        try:
            self._evidence_repository.commit()
        except IntegrityError as error:
            self._evidence_repository.rollback()
            self._compensate_storage(stored.storage_path)
            raise EvidenceConflictError(
                f"Evidence number {evidence_number!r} conflicts with an existing record."
            ) from error
        except SQLAlchemyError as error:
            self._evidence_repository.rollback()
            self._compensate_storage(stored.storage_path)
            raise EvidencePersistenceError("Evidence metadata could not be saved.") from error
        self._logger.info("Registered evidence %s for case %s.", evidence.id, case.id)
        return self._to_dto(evidence)

    def get_evidence(self, evidence_id: UUID) -> EvidenceDTO:
        """Return one active evidence record by identifier."""
        return self._to_dto(self._require_evidence(evidence_id))

    def list_evidence(self, case_id: UUID) -> list[EvidenceDTO]:
        """Return active evidence records linked to one active or archived case."""
        if self._case_repository.get_by_id(case_id) is None:
            raise CaseNotFoundError(f"Case {case_id} was not found.")
        return [self._to_dto(evidence) for evidence in self._evidence_repository.list_for_case(case_id)]

    def delete_evidence(self, evidence_id: UUID) -> EvidenceDTO:
        """Soft-delete evidence metadata while preserving stored bytes for custody integrity."""
        evidence = self._evidence_repository.get_by_id(evidence_id, include_deleted=True)
        if evidence is None:
            raise EvidenceNotFoundError(f"Evidence {evidence_id} was not found.")
        if evidence.deleted_at is None:
            evidence.deleted_at = utc_now()
            try:
                self._evidence_repository.commit()
            except SQLAlchemyError as error:
                self._evidence_repository.rollback()
                raise EvidencePersistenceError("Evidence could not be safely soft-deleted.") from error
            self._logger.warning(
                "Soft-deleted evidence %s from case %s; stored bytes were retained.", evidence.id, evidence.case_id
            )
        return self._to_dto(evidence)

    def _require_evidence(self, evidence_id: UUID) -> Evidence:
        """Return active evidence or raise the service-specific not-found error."""
        evidence = self._evidence_repository.get_by_id(evidence_id)
        if evidence is None:
            raise EvidenceNotFoundError(f"Evidence {evidence_id} was not found.")
        return evidence

    def _compensate_storage(self, storage_path: str) -> None:
        """Try to remove an orphaned upload after a failed database transaction."""
        try:
            self._storage.remove(storage_path)
        except EvidenceStorageError:
            self._logger.critical("Orphaned evidence file requires custody review: %s", storage_path, exc_info=True)

    def _validate_evidence_number(self, value: str) -> str:
        """Normalize and validate a case-scoped evidence reference number."""
        normalized = value.strip().upper()
        if not self._EVIDENCE_NUMBER_PATTERN.fullmatch(normalized):
            raise EvidenceValidationError(
                "Evidence number must contain 1-64 letters, numbers, dots, underscores, or hyphens."
            )
        return normalized

    @staticmethod
    def _validate_filename(value: str) -> str:
        """Validate and normalize an upload filename without accepting a path."""
        normalized = value.strip()
        if not normalized or len(normalized) > 512 or normalized != normalized.replace("\\", "/").split("/")[-1]:
            raise EvidenceValidationError("Evidence filename must be a single filename of at most 512 characters.")
        return normalized

    @staticmethod
    def _validate_source_description(value: str | None) -> str | None:
        """Validate optional provenance information without interpreting the evidence."""
        if value is None:
            return None
        normalized = value.strip()
        if len(normalized) > 10_000:
            raise EvidenceValidationError("Evidence source description must not exceed 10,000 characters.")
        return normalized or None

    @staticmethod
    def _validate_media_type(value: str | None) -> str | None:
        """Validate caller-provided MIME metadata without inspecting file contents."""
        if value is None:
            return None
        normalized = value.strip().lower()
        if not normalized or len(normalized) > 255 or "/" not in normalized:
            raise EvidenceValidationError("Evidence media type must be a valid MIME type.")
        return normalized

    @staticmethod
    def _to_dto(evidence: Evidence) -> EvidenceDTO:
        """Map an evidence persistence model to the public service DTO."""
        return EvidenceDTO(
            id=evidence.id,
            case_id=evidence.case_id,
            evidence_number=evidence.evidence_number,
            original_filename=evidence.original_filename,
            storage_path=evidence.storage_path,
            media_type=evidence.media_type,
            size_bytes=evidence.size_bytes,
            sha256=evidence.sha256,
            source_description=evidence.source_description,
            acquired_at=evidence.acquired_at,
            deleted_at=evidence.deleted_at,
        )
