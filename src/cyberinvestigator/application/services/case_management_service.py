"""Business service for the full lifecycle of investigation cases."""

from __future__ import annotations

import logging
import re
from typing import Final
from uuid import UUID

from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from cyberinvestigator.application.dto.cases import (
    UNSET,
    CaseCreateRequest,
    CaseDTO,
    CaseUpdateRequest,
)
from cyberinvestigator.domain.repositories import CaseRepository
from cyberinvestigator.infrastructure.database.base import utc_now
from cyberinvestigator.infrastructure.database.models import Case
from cyberinvestigator.shared.exceptions import (
    CaseConflictError,
    CaseNotFoundError,
    CasePersistenceError,
    CaseStateError,
    CaseValidationError,
)


class CaseManagementService:
    """Own case validation, lifecycle rules, persistence orchestration, and audit logging."""

    _CASE_NUMBER_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    _ALLOWED_SEVERITIES: Final = frozenset({"critical", "high", "medium", "low", "informational"})

    def __init__(self, repository: CaseRepository, logger: logging.Logger | None = None) -> None:
        """Create a service using explicit repository and logging dependencies."""
        self._repository = repository
        self._logger = logger or logging.getLogger(__name__)

    def create_case(self, request: CaseCreateRequest) -> CaseDTO:
        """Validate, create, persist, and return one new investigation case."""
        case_number = self._validate_case_number(request.case_number)
        title = self._validate_title(request.title)
        description = self._validate_description(request.description)
        severity = self._validate_severity(request.severity)
        if self._repository.get_by_case_number(case_number) is not None:
            raise CaseConflictError(f"Case number {case_number!r} is already in use.")

        case = Case(
            organization_id=getattr(self._repository, "organization_id", None),
            case_number=case_number,
            title=title,
            description=description,
            severity=severity,
        )
        self._repository.add(case)
        self._commit_or_raise("create", case_number)
        self._logger.info("Created investigation case %s (%s).", case.id, case.case_number)
        return self._to_dto(case)

    def get_case(self, case_id: UUID) -> CaseDTO:
        """Return one active or archived case by identifier, excluding soft-deleted cases."""
        return self._to_dto(self._require_case(case_id))

    def list_cases(self, *, include_archived: bool = False) -> list[CaseDTO]:
        """Return all non-deleted cases as consistent DTOs."""
        return [self._to_dto(case) for case in self._repository.list_all(include_archived=include_archived)]

    def update_case(self, case_id: UUID, request: CaseUpdateRequest) -> CaseDTO:
        """Validate and persist permitted changes to an active investigation case."""
        case = self._require_case(case_id)
        self._ensure_mutable(case)
        if request.title is UNSET and request.description is UNSET and request.severity is UNSET:
            raise CaseValidationError("At least one case field must be supplied for update.")
        if request.title is not UNSET:
            case.title = self._validate_title(request.title)
        if request.description is not UNSET:
            case.description = self._validate_description(request.description)
        if request.severity is not UNSET:
            case.severity = self._validate_severity(request.severity)
        self._commit_or_raise("update", case.case_number)
        self._logger.info("Updated investigation case %s (%s).", case.id, case.case_number)
        return self._to_dto(case)

    def close_case(self, case_id: UUID) -> CaseDTO:
        """Close an active case while retaining all evidence and lifecycle history."""
        case = self._require_case(case_id)
        if case.archived_at is not None:
            raise CaseStateError("An archived case cannot be closed.")
        if case.closed_at is None:
            case.closed_at = utc_now()
            self._commit_or_raise("close", case.case_number)
            self._logger.info("Closed investigation case %s (%s).", case.id, case.case_number)
        return self._to_dto(case)

    def archive_case(self, case_id: UUID) -> CaseDTO:
        """Archive a closed case so it is excluded from the default active listing."""
        case = self._require_case(case_id)
        if case.closed_at is None:
            raise CaseStateError("A case must be closed before it can be archived.")
        if case.archived_at is None:
            case.archived_at = utc_now()
            self._commit_or_raise("archive", case.case_number)
            self._logger.info("Archived investigation case %s (%s).", case.id, case.case_number)
        return self._to_dto(case)

    def delete_case(self, case_id: UUID) -> CaseDTO:
        """Soft-delete a case, preserving its records for administrative recovery."""
        case = self._repository.get_by_id(case_id, include_deleted=True)
        if case is None:
            raise CaseNotFoundError(f"Case {case_id} was not found.")
        if case.deleted_at is None:
            case.deleted_at = utc_now()
            self._commit_or_raise("soft-delete", case.case_number)
            self._logger.warning("Soft-deleted investigation case %s (%s).", case.id, case.case_number)
        return self._to_dto(case)

    def _require_case(self, case_id: UUID) -> Case:
        """Return one non-deleted case or raise the service-specific not-found error."""
        case = self._repository.get_by_id(case_id)
        if case is None:
            raise CaseNotFoundError(f"Case {case_id} was not found.")
        return case

    @staticmethod
    def _ensure_mutable(case: Case) -> None:
        """Prevent modification of cases that have already left the active lifecycle."""
        if case.archived_at is not None:
            raise CaseStateError("An archived case cannot be updated.")
        if case.closed_at is not None:
            raise CaseStateError("A closed case cannot be updated.")

    def _commit_or_raise(self, operation: str, case_number: str) -> None:
        """Commit a lifecycle change and translate database failures to custom exceptions."""
        try:
            self._repository.commit()
        except IntegrityError as error:
            self._repository.rollback()
            raise CaseConflictError(f"Case {case_number!r} conflicts with an existing record.") from error
        except SQLAlchemyError as error:
            self._repository.rollback()
            raise CasePersistenceError(f"Unable to {operation} case {case_number!r}.") from error

    def _validate_case_number(self, value: str) -> str:
        """Validate and normalize a human-readable case number."""
        normalized = value.strip().upper()
        if not self._CASE_NUMBER_PATTERN.fullmatch(normalized):
            raise CaseValidationError("Case number must contain 1-64 letters, numbers, dots, underscores, or hyphens.")
        return normalized

    @staticmethod
    def _validate_title(value: str) -> str:
        """Validate and normalize a case title."""
        normalized = value.strip()
        if not normalized or len(normalized) > 255:
            raise CaseValidationError("Case title must contain between 1 and 255 characters.")
        return normalized

    @staticmethod
    def _validate_description(value: str | None) -> str | None:
        """Validate an optional case description while allowing explicit clearing."""
        if value is None:
            return None
        normalized = value.strip()
        if len(normalized) > 10_000:
            raise CaseValidationError("Case description must not exceed 10,000 characters.")
        return normalized or None

    def _validate_severity(self, value: str) -> str:
        """Validate and normalize one supported investigation severity level."""
        normalized = value.strip().lower()
        if normalized not in self._ALLOWED_SEVERITIES:
            allowed = ", ".join(sorted(self._ALLOWED_SEVERITIES))
            raise CaseValidationError(f"Case severity must be one of: {allowed}.")
        return normalized

    @staticmethod
    def _to_dto(case: Case) -> CaseDTO:
        """Map one persistence model to the consistent public case DTO."""
        return CaseDTO(
            id=case.id,
            case_number=case.case_number,
            title=case.title,
            description=case.description,
            severity=case.severity,
            opened_at=case.opened_at,
            closed_at=case.closed_at,
            archived_at=case.archived_at,
            deleted_at=case.deleted_at,
        )
