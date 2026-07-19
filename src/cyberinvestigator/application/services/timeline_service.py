"""Application service for recording timeline events."""

from __future__ import annotations

import logging
from typing import Final
from uuid import UUID

from cyberinvestigator.application.dto.timeline import TimelineDTO
from cyberinvestigator.domain.repositories import TimelineRepository
from cyberinvestigator.infrastructure.database.base import utc_now
from cyberinvestigator.infrastructure.database.models import TimelineEvent


class TimelineService:
    """Record evidence, investigation, plugin, AI reasoning, reports, recommendations, and observations.

    The service is a thin orchestrator around the repository.
    """

    _DEFAULT_OCCURRED_AT: Final = "now"

    def __init__(self, repository: TimelineRepository, logger: logging.Logger | None = None) -> None:
        self._repository = repository
        self._logger = logger or logging.getLogger(__name__)

    # Evidence
    def record_evidence_event(
        self,
        *,
        case_id: UUID,
        evidence_id: UUID,
        event_type: str,
        summary: str,
        details: str | None = None,
        occurred_at=None,
    ) -> TimelineDTO:
        return self._record(
            case_id=case_id,
            evidence_id=evidence_id,
            artifact_id=None,
            event_type=event_type,
            summary=summary,
            details=details,
            occurred_at=occurred_at,
        )

    # Investigation events
    def record_investigation_event(
        self,
        *,
        case_id: UUID,
        event_type: str,
        summary: str,
        details: str | None = None,
        occurred_at=None,
    ) -> TimelineDTO:
        return self._record(
            case_id=case_id,
            evidence_id=None,
            artifact_id=None,
            event_type=event_type,
            summary=summary,
            details=details,
            occurred_at=occurred_at,
        )

    # Plugin execution events
    def record_plugin_execution(
        self,
        *,
        case_id: UUID,
        evidence_id: UUID | None,
        artifact_id: UUID | None,
        event_type: str,
        summary: str,
        details: str | None = None,
        occurred_at=None,
    ) -> TimelineDTO:
        return self._record(
            case_id=case_id,
            evidence_id=evidence_id,
            artifact_id=artifact_id,
            event_type=event_type,
            summary=summary,
            details=details,
            occurred_at=occurred_at,
        )

    # AI reasoning events
    def record_ai_reasoning_event(
        self,
        *,
        case_id: UUID,
        event_type: str,
        summary: str,
        details: str | None = None,
        artifact_id: UUID | None = None,
        evidence_id: UUID | None = None,
        occurred_at=None,
    ) -> TimelineDTO:
        return self._record(
            case_id=case_id,
            evidence_id=evidence_id,
            artifact_id=artifact_id,
            event_type=event_type,
            summary=summary,
            details=details,
            occurred_at=occurred_at,
        )

    # Report generation
    def record_report_generation(
        self,
        *,
        case_id: UUID,
        report_type: str,
        version: int,
        storage_path: str,
        event_type: str,
        occurred_at=None,
    ) -> TimelineDTO:
        summary = f"Report generated: {report_type} v{version}"
        details = storage_path
        return self._record(
            case_id=case_id,
            evidence_id=None,
            artifact_id=None,
            event_type=event_type,
            summary=summary,
            details=details,
            occurred_at=occurred_at,
        )

    # Recommendations
    def record_recommendation(
        self,
        *,
        case_id: UUID,
        event_type: str,
        summary: str,
        details: str | None = None,
        occurred_at=None,
    ) -> TimelineDTO:
        return self._record(
            case_id=case_id,
            evidence_id=None,
            artifact_id=None,
            event_type=event_type,
            summary=summary,
            details=details,
            occurred_at=occurred_at,
        )

    # Observations
    def record_observation(
        self,
        *,
        case_id: UUID,
        artifact_id: UUID,
        event_type: str,
        summary: str,
        details: str | None = None,
        occurred_at=None,
    ) -> TimelineDTO:
        return self._record(
            case_id=case_id,
            evidence_id=None,
            artifact_id=artifact_id,
            event_type=event_type,
            summary=summary,
            details=details,
            occurred_at=occurred_at,
        )

    def _record(
        self,
        *,
        case_id: UUID,
        evidence_id: UUID | None,
        artifact_id: UUID | None,
        event_type: str,
        summary: str,
        details: str | None,
        occurred_at=None,
    ) -> TimelineDTO:
        occurred = occurred_at if occurred_at is not None else utc_now()
        event = TimelineEvent(
            case_id=case_id,
            evidence_id=evidence_id,
            artifact_id=artifact_id,
            occurred_at=occurred,
            event_type=event_type,
            summary=summary,
            details=details,
        )
        self._repository.add(event)
        self._repository.commit()
        self._logger.info("Recorded timeline event %s for case %s.", event.id, case_id)
        return TimelineDTO(
            id=event.id,
            case_id=event.case_id,
            evidence_id=event.evidence_id,
            artifact_id=event.artifact_id,
            occurred_at=event.occurred_at,
            event_type=event.event_type,
            summary=event.summary,
            details=event.details,
        )
