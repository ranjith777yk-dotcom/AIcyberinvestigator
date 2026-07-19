"""Unit tests for deterministic investigation planning."""

from cyberinvestigator.domain.entities import ArtifactItem, InvestigationState
from cyberinvestigator.domain.services import InvestigationPlanner


def test_build_plan_contains_ordered_defensible_stages(investigation_state: InvestigationState) -> None:
    """The planner returns the standard stage sequence for every case."""
    plan = InvestigationPlanner().build_plan(investigation_state)

    assert plan.case_id == investigation_state.case.case_id
    assert [stage.identifier for stage in plan.stages] == [
        "preservation",
        "triage",
        "correlation",
        "hypothesis_validation",
        "reporting",
    ]


def test_build_plan_adds_artifact_correlation_hypothesis(investigation_state: InvestigationState) -> None:
    """Artifact presence adds a structural correlation hypothesis."""
    investigation_state.artifacts.append(
        ArtifactItem(
            artifact_id=investigation_state.case.case_id,
            evidence_id=investigation_state.evidence[0].evidence_id,
            artifact_type="file",
            name="artifact",
        )
    )

    plan = InvestigationPlanner().build_plan(investigation_state)

    assert "artifact_correlation" in {hypothesis.identifier for hypothesis in plan.hypotheses}
    assert all("{" not in hypothesis.statement for hypothesis in plan.hypotheses)
