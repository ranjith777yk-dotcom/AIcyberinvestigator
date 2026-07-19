"""Deterministic investigator-question generation without AI or tool execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4

from cyberinvestigator.domain.entities.investigation_state import (
    ArtifactItem,
    EvidenceItem,
    InvestigationState,
)


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp for question-set metadata."""
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True, kw_only=True)
class InvestigatorQuestion:
    """A traceable question generated from non-sensitive investigation structure."""

    question_id: UUID = field(default_factory=uuid4)
    text: str
    rationale: str
    evidence_id: UUID | None = None
    artifact_id: UUID | None = None
    observation_id: UUID | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class QuestionSet:
    """Immutable collection of investigator questions for one case."""

    case_id: UUID
    questions: tuple[InvestigatorQuestion, ...]
    generated_at: datetime = field(default_factory=utc_now)


class QuestionEngine:
    """Generate structured investigator questions from the current state.

    The engine evaluates artifact types, evidence presence, available metadata,
    and recorded timeline observations. It never invokes tools, providers, or
    models, and it does not expose raw evidence or artifact content.
    """

    _ARTIFACT_QUESTION_TEMPLATES: dict[str, tuple[str, str]] = {
        "browser_history": (
            "Which recorded timeline observations corroborate browser activity?",
            "Browser-history artifacts benefit from time-based corroboration.",
        ),
        "event_log": (
            "Which related observations establish the sequence around this event-log artifact?",
            "Event-log artifacts require sequence and source correlation.",
        ),
        "file": (
            "What provenance and timeline context support this file artifact?",
            "File artifacts should be assessed through provenance and temporal context.",
        ),
        "network_connection": (
            "Which observations corroborate the timing and scope of this network artifact?",
            "Network artifacts require correlation with independent observations.",
        ),
        "process": (
            "Which recorded observations establish the lifecycle of this process artifact?",
            "Process artifacts should be correlated with their surrounding activity.",
        ),
        "registry": (
            "What evidence and timeline observations support this registry artifact?",
            "Registry artifacts require source and temporal corroboration.",
        ),
    }

    def generate_questions(self, state: InvestigationState) -> QuestionSet:
        """Generate a structured, deterministic question set for a case."""
        questions: list[InvestigatorQuestion] = []
        for evidence in state.evidence:
            questions.extend(self._questions_for_evidence(evidence))
        for artifact in state.artifacts:
            questions.append(self._question_for_artifact(artifact))
        questions.extend(self._questions_for_observations(state))

        return QuestionSet(case_id=state.case.case_id, questions=tuple(questions))

    def _questions_for_evidence(self, evidence: EvidenceItem) -> tuple[InvestigatorQuestion, ...]:
        """Generate provenance and metadata questions for one evidence record."""
        questions = [
            InvestigatorQuestion(
                text="Is the acquisition provenance for this evidence record complete and traceable?",
                rationale="Every evidence item requires a documented provenance assessment.",
                evidence_id=evidence.evidence_id,
            )
        ]
        if evidence.media_type:
            questions.append(
                InvestigatorQuestion(
                    text="Does the recorded media classification align with the planned analysis scope?",
                    rationale="Media classification is available in the evidence metadata.",
                    evidence_id=evidence.evidence_id,
                )
            )
        if evidence.size_bytes is not None:
            questions.append(
                InvestigatorQuestion(
                    text="Does the recorded evidence size indicate that acquisition completeness should be reviewed?",
                    rationale="Evidence size is available in the acquisition metadata.",
                    evidence_id=evidence.evidence_id,
                )
            )
        if evidence.acquired_at is not None:
            questions.append(
                InvestigatorQuestion(
                    text="How does the acquisition time relate to the recorded investigation timeline?",
                    rationale="Acquisition time is available for temporal correlation.",
                    evidence_id=evidence.evidence_id,
                )
            )
        return tuple(questions)

    def _question_for_artifact(self, artifact: ArtifactItem) -> InvestigatorQuestion:
        """Generate an artifact-type-specific question without exposing artifact content."""
        artifact_type = artifact.artifact_type.strip().lower().replace(" ", "_")
        template = self._ARTIFACT_QUESTION_TEMPLATES.get(
            artifact_type,
            (
                "What evidence provenance and timeline observations corroborate this artifact?",
                "Artifact type has no specialised deterministic question template.",
            ),
        )
        return InvestigatorQuestion(
            text=template[0],
            rationale=template[1],
            evidence_id=artifact.evidence_id,
            artifact_id=artifact.artifact_id,
        )

    def _questions_for_observations(self, state: InvestigationState) -> tuple[InvestigatorQuestion, ...]:
        """Generate correlation questions from previously recorded observations."""
        if not state.timeline:
            return ()

        return tuple(
            InvestigatorQuestion(
                text="Which independent records corroborate this timeline observation?",
                rationale="Previously recorded observations should be independently corroborated.",
                observation_id=observation.event_id,
                evidence_id=observation.evidence_id,
                artifact_id=observation.artifact_id,
            )
            for observation in state.timeline
        )
