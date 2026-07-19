"""Integration tests for custody-preserving evidence management."""

from __future__ import annotations

import hashlib
from io import BytesIO

import pytest

from cyberinvestigator import create_app
from cyberinvestigator.application.dto import CaseCreateRequest, EvidenceAddRequest
from cyberinvestigator.application.services import CaseManagementService, EvidenceService
from cyberinvestigator.infrastructure.evidence_storage import LocalEvidenceStorage
from cyberinvestigator.infrastructure.repositories import SQLAlchemyCaseRepository, SQLAlchemyEvidenceRepository
from cyberinvestigator.shared.exceptions import EvidenceConflictError, EvidenceNotFoundError


@pytest.fixture
def evidence_service(tmp_path):
    """Return an evidence service using isolated SQLite and filesystem storage."""
    app = create_app("testing")
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        database.create_all()
        case_repository = SQLAlchemyCaseRepository(database.session)
        service = EvidenceService(
            case_repository,
            SQLAlchemyEvidenceRepository(database.session),
            LocalEvidenceStorage(tmp_path / "evidence"),
        )
        case_service = CaseManagementService(case_repository)
        yield service, case_service, tmp_path / "evidence"
        database.session.remove()
        database.drop_all()


def test_evidence_service_stores_custody_metadata_and_retains_soft_deleted_bytes(evidence_service) -> None:
    """Evidence is hashed while copied, linked to its case, and safely soft-deleted."""
    service, case_service, storage_root = evidence_service
    case = case_service.create_case(CaseCreateRequest(case_number="CASE-200", title="Evidence custody"))
    content = b"forensic evidence bytes\x00\xff"

    created = service.add_evidence(
        EvidenceAddRequest(
            case_id=case.id,
            evidence_number="EV-001",
            filename="acquisition.pdf",
            content=BytesIO(content),
            source_description="Acquired from approved collection channel.",
        )
    )

    assert created.case_id == case.id
    assert created.size_bytes == len(content)
    assert created.sha256 == hashlib.sha256(content).hexdigest()
    assert created.media_type == "application/pdf"
    assert (storage_root / created.storage_path).read_bytes() == content
    assert service.get_evidence(created.id).id == created.id
    assert [item.id for item in service.list_evidence(case.id)] == [created.id]

    deleted = service.delete_evidence(created.id)

    assert deleted.deleted_at is not None
    assert (storage_root / created.storage_path).exists()
    assert service.list_evidence(case.id) == []
    with pytest.raises(EvidenceNotFoundError):
        service.get_evidence(created.id)


def test_evidence_service_rejects_duplicate_case_evidence_numbers(evidence_service) -> None:
    """A case-scoped evidence number remains unique without overwriting bytes."""
    service, case_service, _ = evidence_service
    case = case_service.create_case(CaseCreateRequest(case_number="CASE-201", title="Duplicate prevention"))
    request = EvidenceAddRequest(
        case_id=case.id,
        evidence_number="EV-001",
        filename="first.bin",
        content=BytesIO(b"first"),
    )
    service.add_evidence(request)

    with pytest.raises(EvidenceConflictError):
        service.add_evidence(
            EvidenceAddRequest(
                case_id=case.id,
                evidence_number="EV-001",
                filename="second.bin",
                content=BytesIO(b"second"),
            )
        )
