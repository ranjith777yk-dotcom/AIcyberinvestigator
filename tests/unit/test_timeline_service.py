from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from cyberinvestigator.application.services.timeline_service import TimelineService
from cyberinvestigator.domain.repositories.timeline_repository import TimelineRepository


@dataclass
class Captured:
    added: list
    committed: int


class FakeRepo(TimelineRepository):
    def __init__(self) -> None:
        self.capture = Captured(added=[], committed=0)

    def add(self, event):
        self.capture.added.append(event)

    def commit(self) -> None:
        self.capture.committed += 1

    def rollback(self) -> None:
        pass


def test_record_evidence_event_adds_timeline_event() -> None:
    repo = FakeRepo()
    service = TimelineService(repository=repo)

    case_id = UUID("11111111-1111-1111-1111-111111111111")
    evidence_id = UUID("22222222-2222-2222-2222-222222222222")
    occurred_at = datetime(2024, 1, 1, tzinfo=timezone.utc)

    dto = service.record_evidence_event(
        case_id=case_id,
        evidence_id=evidence_id,
        event_type="evidence.acquired",
        summary="Evidence acquired",
        details="details",
        occurred_at=occurred_at,
    )

    assert repo.capture.committed == 1
    assert len(repo.capture.added) == 1
    event = repo.capture.added[0]

    assert event.case_id == case_id
    assert event.evidence_id == evidence_id
    assert event.artifact_id is None
    assert event.event_type == "evidence.acquired"
    assert event.summary == "Evidence acquired"
    assert event.details == "details"
    assert event.occurred_at == occurred_at

    assert dto.case_id == case_id
    assert dto.evidence_id == evidence_id
    assert dto.event_type == "evidence.acquired"


def test_record_observation_sets_artifact_id() -> None:
    repo = FakeRepo()
    service = TimelineService(repository=repo)

    case_id = UUID("11111111-1111-1111-1111-111111111111")
    artifact_id = UUID("33333333-3333-3333-3333-333333333333")

    dto = service.record_observation(
        case_id=case_id,
        artifact_id=artifact_id,
        event_type="observation.detected",
        summary="Malicious behavior detected",
        details=None,
    )

    assert len(repo.capture.added) == 1
    event = repo.capture.added[0]
    assert event.artifact_id == artifact_id
    assert event.evidence_id is None
    assert event.details is None
    assert dto.artifact_id == artifact_id
