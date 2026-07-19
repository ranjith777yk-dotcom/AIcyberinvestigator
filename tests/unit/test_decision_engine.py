"""Unit tests for deterministic, non-executing decisions."""

import pytest

from cyberinvestigator.domain.entities import ArtifactItem, InvestigationState
from cyberinvestigator.domain.services import (
    DecisionEngine,
    DecisionPriority,
    QuestionEngine,
    QuestionSet,
)


def test_decision_prioritises_artifact_linked_question(investigation_state: InvestigationState) -> None:
    """Artifact-backed questions produce the artifact correlation recommendation."""
    investigation_state.artifacts.append(
        ArtifactItem(
            artifact_id=investigation_state.case.case_id,
            evidence_id=investigation_state.evidence[0].evidence_id,
            artifact_type="file",
            name="artifact",
        )
    )
    questions = QuestionEngine().generate_questions(investigation_state)

    decision = DecisionEngine().decide(investigation_state.evidence, questions, investigation_state)

    assert decision.suggested_tool == "Artifact Timeline Correlator"
    assert decision.priority is DecisionPriority.HIGH
    assert decision.question_id is not None


def test_decision_rejects_questions_for_another_case(
    investigation_state: InvestigationState, unrelated_case_id
) -> None:
    """Question sets must remain bound to the same case as their decision state."""
    questions = QuestionSet(case_id=unrelated_case_id, questions=())

    with pytest.raises(ValueError, match="case_id"):
        DecisionEngine().decide(investigation_state.evidence, questions, investigation_state)
