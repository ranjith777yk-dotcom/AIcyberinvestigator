from __future__ import annotations

from concurrent.futures import Future

from cyberinvestigator import create_app
from cyberinvestigator.application.ports.analysis_runner import AnalysisRequest
from cyberinvestigator.application.services import CaseManagementService, EvidenceService
from cyberinvestigator.application.services.timeline_service import TimelineService
from cyberinvestigator.infrastructure.jobs import InProcessJobDispatcher


class RecordingExecutor:
    def __init__(self) -> None:
        self.tasks = []

    def submit(self, fn, /, *args, **kwargs):
        self.tasks.append((fn, args, kwargs))
        return Future()


def test_feature_registry_composes_existing_use_cases_per_application() -> None:
    app = create_app("testing")
    features = app.extensions["cyberinvestigator_features"]
    assert app.extensions["cyberinvestigator"]["features"] is features
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        assert isinstance(features.cases.service(database.session, app.logger), CaseManagementService)
        assert isinstance(features.evidence.service(database.session, app.logger), EvidenceService)
        assert isinstance(features.timeline.service(database.session, app.logger), TimelineService)
    assert features.ai.providers is app.extensions["cyberinvestigator_ai_registry"]


def test_in_process_dispatcher_implements_replaceable_job_boundary() -> None:
    executor = RecordingExecutor()
    dispatcher = InProcessJobDispatcher(executor)

    def task() -> None:
        pass

    dispatcher.submit(task)
    assert executor.tasks == [(task, (), {})]


def test_analysis_request_is_an_immutable_provider_neutral_contract() -> None:
    from uuid import uuid4

    request = AnalysisRequest(
        evidence_id=uuid4(),
        case_id=uuid4(),
        storage_path="case/evidence.bin",
        sha256="a" * 64,
        analyzer="static-forensics",
        limits={"memory_mb": 512, "timeout_seconds": 60},
    )
    assert request.analyzer == "static-forensics"
    assert request.limits["timeout_seconds"] == 60
