"""Typed report assembly without analysis, AI generation, or rendering."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol
from uuid import UUID, uuid4

from cyberinvestigator.domain.entities.investigation_state import (
    CaseMetadata,
    ConfidenceAssessment,
    EvidenceItem,
    PluginOutput,
    RecommendationItem,
    TimelineEntry,
)


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp for report creation metadata."""
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True, kw_only=True)
class ReportObservation:
    """A traceable observation included in a formal investigation report."""

    observation_id: UUID = field(default_factory=uuid4)
    summary: str
    details: str | None = None
    evidence_id: UUID | None = None
    artifact_id: UUID | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class MitreAttackMapping:
    """A reported MITRE ATT&CK technique mapping with supporting references."""

    technique_id: str
    technique_name: str
    tactic: str
    evidence_ids: tuple[UUID, ...] = ()
    observation_ids: tuple[UUID, ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class IndicatorOfCompromise:
    """An IOC explicitly supplied for inclusion in an investigation report."""

    indicator_type: str
    value: str
    confidence: float | None = None
    source_reference: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ReportRequest:
    """All supplied sections required to assemble an investigation report."""

    case: CaseMetadata
    executive_summary: str
    technical_summary: str
    timeline: tuple[TimelineEntry, ...] = ()
    evidence: tuple[EvidenceItem, ...] = ()
    observations: tuple[ReportObservation, ...] = ()
    recommendations: tuple[RecommendationItem, ...] = ()
    confidence: tuple[ConfidenceAssessment, ...] = ()
    plugin_outputs: tuple[PluginOutput, ...] = ()
    mitre_attack_mappings: tuple[MitreAttackMapping, ...] = ()
    indicators_of_compromise: tuple[IndicatorOfCompromise, ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class InvestigationReport:
    """Immutable, complete report document ready for a presentation renderer."""

    report_id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=utc_now)
    case: CaseMetadata
    executive_summary: str
    technical_summary: str
    timeline: tuple[TimelineEntry, ...]
    evidence: tuple[EvidenceItem, ...]
    observations: tuple[ReportObservation, ...]
    recommendations: tuple[RecommendationItem, ...]
    confidence: tuple[ConfidenceAssessment, ...]
    plugin_outputs: tuple[PluginOutput, ...]
    mitre_attack_mappings: tuple[MitreAttackMapping, ...]
    indicators_of_compromise: tuple[IndicatorOfCompromise, ...]


class ReportRenderer(Protocol):
    """Presentation boundary for rendering a complete investigation report."""

    def render_html(self, report: InvestigationReport) -> str:
        """Render one report document into HTML."""
        ...


class ReportEngine:
    """Assemble report documents from explicitly provided investigation facts.

    The engine neither derives findings nor renders HTML. It preserves the
    supplied report sections so that independent presentation adapters can
    render a reviewable document.
    """

    def build_report(self, request: ReportRequest) -> InvestigationReport:
        """Return an immutable report document composed from the supplied request."""
        return InvestigationReport(
            case=request.case,
            executive_summary=request.executive_summary,
            technical_summary=request.technical_summary,
            timeline=request.timeline,
            evidence=request.evidence,
            observations=request.observations,
            recommendations=request.recommendations,
            confidence=request.confidence,
            plugin_outputs=request.plugin_outputs,
            mitre_attack_mappings=request.mitre_attack_mappings,
            indicators_of_compromise=request.indicators_of_compromise,
        )
