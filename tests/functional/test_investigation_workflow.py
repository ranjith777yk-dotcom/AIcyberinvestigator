"""Functional tests for the deterministic investigation workflow boundaries."""

from cyberinvestigator.domain.entities import ArtifactItem, InvestigationState
from cyberinvestigator.domain.services import (
    DecisionEngine,
    InvestigationPlanner,
    QuestionEngine,
    ReportEngine,
    ReportRequest,
)


def test_investigation_workflow_builds_plan_questions_decision_and_report(
    investigation_state: InvestigationState,
) -> None:
    """Core deterministic components compose without AI, tools, or persistence."""
    investigation_state.artifacts.append(
        ArtifactItem(
            artifact_id=investigation_state.case.case_id,
            evidence_id=investigation_state.evidence[0].evidence_id,
            artifact_type="file",
            name="artifact",
        )
    )

    plan = InvestigationPlanner().build_plan(investigation_state)
    questions = QuestionEngine().generate_questions(investigation_state)
    decision = DecisionEngine().decide(investigation_state.evidence, questions, investigation_state)
    report = ReportEngine().build_report(
        ReportRequest(
            case=investigation_state.case,
            executive_summary="Investigation report prepared for review.",
            technical_summary="Deterministic workflow validation.",
            evidence=tuple(investigation_state.evidence),
        )
    )

    assert plan.case_id == investigation_state.case.case_id
    assert questions.case_id == investigation_state.case.case_id
    assert decision.case_id == investigation_state.case.case_id
    assert report.case.case_id == investigation_state.case.case_id
