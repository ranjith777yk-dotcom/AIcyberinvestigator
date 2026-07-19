"""Integration tests for repository-backed case management."""

from __future__ import annotations

from uuid import uuid4

import pytest

from cyberinvestigator import create_app
from cyberinvestigator.application.dto import CaseCreateRequest, CaseUpdateRequest
from cyberinvestigator.application.services import CaseManagementService
from cyberinvestigator.infrastructure.repositories import SQLAlchemyCaseRepository
from cyberinvestigator.shared.exceptions import CaseNotFoundError, CaseStateError, CaseValidationError


@pytest.fixture
def case_service() -> CaseManagementService:
    """Return a case service backed by the isolated testing SQLite database."""
    app = create_app("testing")
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        database.create_all()
        service = CaseManagementService(SQLAlchemyCaseRepository(database.session))
        yield service
        database.session.remove()
        database.drop_all()


def test_case_service_manages_full_soft_delete_lifecycle(case_service: CaseManagementService) -> None:
    """Create, update, close, archive, list, and soft-delete a case consistently."""
    created = case_service.create_case(
        CaseCreateRequest(case_number="case-100", title="Initial investigation", severity="high")
    )
    updated = case_service.update_case(created.id, CaseUpdateRequest(title="Updated investigation"))
    closed = case_service.close_case(created.id)
    archived = case_service.archive_case(created.id)
    deleted = case_service.delete_case(created.id)

    assert created.case_number == "CASE-100"
    assert updated.title == "Updated investigation"
    assert closed.closed_at is not None
    assert archived.archived_at is not None
    assert deleted.deleted_at is not None
    assert case_service.list_cases() == []
    with pytest.raises(CaseNotFoundError):
        case_service.get_case(created.id)


def test_case_service_validates_lifecycle_and_input(case_service: CaseManagementService) -> None:
    """Invalid input and invalid lifecycle transitions use custom service exceptions."""
    with pytest.raises(CaseValidationError):
        case_service.create_case(CaseCreateRequest(case_number="invalid space", title="Case"))

    created = case_service.create_case(CaseCreateRequest(case_number="CASE-101", title="Open case"))
    with pytest.raises(CaseStateError):
        case_service.archive_case(created.id)
    with pytest.raises(CaseNotFoundError):
        case_service.get_case(uuid4())
