from __future__ import annotations

from datetime import datetime, timezone

from cyberinvestigator.infrastructure.database.models import Case, Evidence, TimelineEvent
from cyberinvestigator.infrastructure.repositories.sqlalchemy_case_repository import SQLAlchemyCaseRepository
from cyberinvestigator.infrastructure.repositories.sqlalchemy_evidence_repository import SQLAlchemyEvidenceRepository
from cyberinvestigator.infrastructure.repositories.timeline_repository import SQLAlchemyTimelineRepository


def test_sqlalchemy_timeline_repository_persists_timeline_event(db_session) -> None:
    # Arrange: create minimal case and evidence to satisfy FK constraints
    case_repo = SQLAlchemyCaseRepository(db_session)

    case = Case(case_number="CASE-INT", title="Integration")
    case_repo.add(case)
    case_repo.commit()

    evidence_repo = SQLAlchemyEvidenceRepository(db_session)
    evidence = Evidence(
        case_id=case.id,
        evidence_number="E-INT",
        original_filename="evidence.pdf",
        storage_path="/evidence/evidence.pdf",
        media_type="application/pdf",
        size_bytes=1,
        sha256="a" * 64,
        source_description=None,
    )
    evidence_repo.add(evidence)
    evidence_repo.commit()

    repo = SQLAlchemyTimelineRepository(db_session)

    occurred_at = datetime(2024, 2, 2, tzinfo=timezone.utc)
    event = TimelineEvent(
        case_id=case.id,
        evidence_id=evidence.id,
        artifact_id=None,
        occurred_at=occurred_at,
        event_type="evidence.acquired",
        summary="Integration evidence",
        details="ok",
    )

    # Act
    repo.add(event)
    repo.commit()

    # Assert
    persisted = db_session.query(TimelineEvent).filter(TimelineEvent.id == event.id).one()
    assert persisted.case_id == case.id
    assert persisted.evidence_id == evidence.id
    assert persisted.event_type == "evidence.acquired"
    assert persisted.summary == "Integration evidence"
    assert persisted.details == "ok"
    # SQLite DATE/TIME handling may drop tzinfo when persisting/reloading.
    assert persisted.occurred_at.replace(tzinfo=timezone.utc) == occurred_at
