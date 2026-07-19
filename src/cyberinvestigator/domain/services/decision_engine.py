"""Deterministic decision generation without tool execution or AI calls."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Sequence
from uuid import UUID, uuid4

from cyberinvestigator.domain.entities.investigation_state import EvidenceItem, InvestigationState
from cyberinvestigator.domain.services.question_engine import InvestigatorQuestion, QuestionSet


class DecisionPriority(str, Enum):
    """Supported priority levels for a suggested investigation decision."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True, slots=True, kw_only=True)
class Decision:
    """A non-executable, traceable recommendation for the next investigation step."""

    decision_id: UUID = field(default_factory=uuid4)
    case_id: UUID
    decision: str
    suggested_tool: str
    reason: str
    priority: DecisionPriority
    expected_output: str
    confidence: float
    question_id: UUID | None = None


class DecisionEngine:
    """Produce one safe and deterministic decision from investigation inputs.

    The engine classifies the available question references and evidence
    availability. It returns descriptive tool suggestions only; it never loads,
    executes, dispatches, or otherwise interacts with tools or AI providers.
    """

    def decide(
        self,
        evidence: Sequence[EvidenceItem],
        questions: QuestionSet,
        state: InvestigationState,
    ) -> Decision:
        """Return the highest-context non-executing decision for a case.

        Raises:
            ValueError: If the question set does not belong to the supplied
                investigation state.
        """
        if questions.case_id != state.case.case_id:
            raise ValueError("QuestionSet case_id must match InvestigationState case_id.")

        if not evidence:
            return self._no_evidence_decision(state.case.case_id)

        question = self._select_question(questions.questions)
        if question is None:
            return self._evidence_inventory_decision(state.case.case_id)
        if question.artifact_id is not None:
            return self._artifact_decision(state.case.case_id, question)
        if question.observation_id is not None:
            return self._timeline_decision(state.case.case_id, question)
        return self._metadata_decision(state.case.case_id, question)

    @staticmethod
    def _select_question(questions: Sequence[InvestigatorQuestion]) -> InvestigatorQuestion | None:
        """Select the most context-rich question without inspecting its content."""
        for question in questions:
            if question.artifact_id is not None:
                return question
        for question in questions:
            if question.observation_id is not None:
                return question
        return questions[0] if questions else None

    @staticmethod
    def _no_evidence_decision(case_id: UUID) -> Decision:
        """Create the decision used when no evidence input is available."""
        return Decision(
            case_id=case_id,
            decision="Establish the available evidence scope.",
            suggested_tool="Evidence Intake Review",
            reason="No evidence records were supplied to support a further assessment.",
            priority=DecisionPriority.HIGH,
            expected_output="A traceable inventory of available evidence records.",
            confidence=0.95,
        )

    @staticmethod
    def _evidence_inventory_decision(case_id: UUID) -> Decision:
        """Create the decision used when evidence exists but no questions exist."""
        return Decision(
            case_id=case_id,
            decision="Review available evidence metadata before forming further questions.",
            suggested_tool="Evidence Metadata Inspector",
            reason="Evidence records exist, but no investigator question is available for prioritisation.",
            priority=DecisionPriority.MEDIUM,
            expected_output="A metadata-oriented evidence scope summary.",
            confidence=0.8,
        )

    @staticmethod
    def _artifact_decision(case_id: UUID, question: InvestigatorQuestion) -> Decision:
        """Create an artifact-correlation decision for an artifact-linked question."""
        return Decision(
            case_id=case_id,
            question_id=question.question_id,
            decision="Correlate the referenced artifact with available evidence and timeline records.",
            suggested_tool="Artifact Timeline Correlator",
            reason="The highest-context investigator question is linked to an artifact.",
            priority=DecisionPriority.HIGH,
            expected_output="Traceable artifact-to-evidence and artifact-to-timeline correlations.",
            confidence=0.85,
        )

    @staticmethod
    def _timeline_decision(case_id: UUID, question: InvestigatorQuestion) -> Decision:
        """Create a timeline-correlation decision for an observation-linked question."""
        return Decision(
            case_id=case_id,
            question_id=question.question_id,
            decision="Correlate the referenced observation with independent case records.",
            suggested_tool="Timeline Correlator",
            reason="The selected investigator question is linked to a prior observation.",
            priority=DecisionPriority.HIGH,
            expected_output="A corroborated sequence of related timeline observations.",
            confidence=0.8,
        )

    @staticmethod
    def _metadata_decision(case_id: UUID, question: InvestigatorQuestion) -> Decision:
        """Create an evidence-metadata decision for a general investigator question."""
        return Decision(
            case_id=case_id,
            question_id=question.question_id,
            decision="Review metadata associated with the referenced evidence record.",
            suggested_tool="Evidence Metadata Inspector",
            reason="The selected investigator question is not linked to an artifact or observation.",
            priority=DecisionPriority.MEDIUM,
            expected_output="A traceable metadata assessment for the referenced evidence.",
            confidence=0.75,
        )
