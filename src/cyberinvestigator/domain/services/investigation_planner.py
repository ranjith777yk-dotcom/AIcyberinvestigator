"""Deterministic, non-executing investigation planning service.

The planner produces a structured plan from an investigation state.  It never
invokes tools or AI providers, and it never copies evidence content, artifact
content, questions, hypotheses, or any flag-like material into its output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4

from cyberinvestigator.domain.entities.investigation_state import InvestigationState


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp for plan creation metadata."""
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True, kw_only=True)
class InvestigationStage:
    """A non-executable stage in a structured investigation plan."""

    identifier: str
    name: str
    objective: str
    depends_on: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class PlannedHypothesis:
    """A generic, testable proposition for an investigation plan."""

    identifier: str
    statement: str
    validation_focus: str


@dataclass(frozen=True, slots=True, kw_only=True)
class InvestigationStrategy:
    """A safe, high-level strategy with no executable instructions."""

    objective: str
    priorities: tuple[str, ...]
    safeguards: tuple[str, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class InvestigationPlan:
    """Immutable structured plan generated for one investigation case."""

    plan_id: UUID = field(default_factory=uuid4)
    case_id: UUID
    stages: tuple[InvestigationStage, ...]
    hypotheses: tuple[PlannedHypothesis, ...]
    strategy: InvestigationStrategy
    created_at: datetime = field(default_factory=utc_now)


class InvestigationPlanner:
    """Build safe, non-executing plans for reusable investigation state.

    This planner intentionally works only with structural state signals such as
    the presence of evidence and artifacts.  It does not expose raw case data,
    call external services, or direct a tool to perform an action.
    """

    def build_plan(self, state: InvestigationState) -> InvestigationPlan:
        """Build and return a complete structured plan for an investigation."""
        return InvestigationPlan(
            case_id=state.case.case_id,
            stages=self.determine_stages(),
            hypotheses=self.create_hypotheses(state),
            strategy=self.suggest_strategy(state),
        )

    def determine_stages(self) -> tuple[InvestigationStage, ...]:
        """Return the standard ordered stages for a defensible investigation."""
        return (
            InvestigationStage(
                identifier="preservation",
                name="Preservation",
                objective="Maintain source integrity and investigation traceability.",
            ),
            InvestigationStage(
                identifier="triage",
                name="Triage",
                objective="Establish the available evidence and artifact scope.",
                depends_on=("preservation",),
            ),
            InvestigationStage(
                identifier="correlation",
                name="Correlation",
                objective="Correlate recorded observations across the case timeline.",
                depends_on=("triage",),
            ),
            InvestigationStage(
                identifier="hypothesis_validation",
                name="Hypothesis Validation",
                objective="Assess planned hypotheses against traceable findings.",
                depends_on=("correlation",),
            ),
            InvestigationStage(
                identifier="reporting",
                name="Reporting",
                objective="Prepare a defensible summary of supported conclusions.",
                depends_on=("hypothesis_validation",),
            ),
        )

    def create_hypotheses(self, state: InvestigationState) -> tuple[PlannedHypothesis, ...]:
        """Create generic hypotheses using only structural state indicators."""
        hypotheses = [
            PlannedHypothesis(
                identifier="evidence_integrity",
                statement="Available source records can be evaluated with preserved provenance.",
                validation_focus="Evidence identifiers, acquisition metadata, and integrity records.",
            )
        ]
        if state.evidence:
            hypotheses.append(
                PlannedHypothesis(
                    identifier="evidence_scope",
                    statement="Available evidence provides material for scoped investigative analysis.",
                    validation_focus="Evidence coverage and traceable source associations.",
                )
            )
        if state.artifacts:
            hypotheses.append(
                PlannedHypothesis(
                    identifier="artifact_correlation",
                    statement="Recorded artifacts can be correlated with case timeline observations.",
                    validation_focus="Artifact provenance, timestamps, and linked timeline records.",
                )
            )
        return tuple(hypotheses)

    def suggest_strategy(self, state: InvestigationState) -> InvestigationStrategy:
        """Return a high-level, non-executable strategy for the current state."""
        priorities = [
            "Preserve provenance and chain-of-custody context.",
            "Prioritize traceable correlations over unsupported inference.",
        ]
        if state.evidence:
            priorities.append("Review recorded evidence scope before forming conclusions.")
        else:
            priorities.append("Establish evidence scope before forming conclusions.")
        if state.artifacts:
            priorities.append("Align artifact observations with the recorded timeline.")

        return InvestigationStrategy(
            objective="Produce evidence-grounded, traceable investigative conclusions.",
            priorities=tuple(priorities),
            safeguards=(
                "Do not execute tools from the plan.",
                "Do not invoke AI providers from the plan.",
                "Do not include flags, secrets, or raw evidentiary content in the plan.",
            ),
        )
