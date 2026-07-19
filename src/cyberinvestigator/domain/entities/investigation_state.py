"""Reusable, framework-independent investigation state data structures.

These dataclasses describe an investigation snapshot shared by AI, plugin, and
forensic engines.  They deliberately contain no workflow or persistence logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Mapping
from uuid import UUID, uuid4


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp for state metadata."""
    return datetime.now(timezone.utc)


@dataclass(slots=True, kw_only=True)
class CaseMetadata:
    """Identity and descriptive information for the active investigation case."""

    case_id: UUID
    case_number: str
    title: str
    description: str | None = None
    severity: str = "medium"
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)


@dataclass(slots=True, kw_only=True)
class EvidenceItem:
    """Engine-neutral evidence reference and acquisition metadata."""

    evidence_id: UUID
    evidence_number: str
    filename: str
    sha256: str
    storage_path: str
    media_type: str | None = None
    size_bytes: int | None = None
    acquired_at: datetime | None = None


@dataclass(slots=True, kw_only=True)
class ArtifactItem:
    """An artifact reference derived from a specific evidence item."""

    artifact_id: UUID
    evidence_id: UUID
    artifact_type: str
    name: str
    source_location: str | None = None
    parent_artifact_id: UUID | None = None
    observed_at: datetime | None = None


@dataclass(slots=True, kw_only=True)
class InvestigationQuestion:
    """A question recorded for investigation or engine analysis."""

    question_id: UUID = field(default_factory=uuid4)
    text: str = ""
    context: str | None = None
    answer: str | None = None
    source_engine: str | None = None


@dataclass(slots=True, kw_only=True)
class Hypothesis:
    """A testable investigative hypothesis and its supporting references."""

    hypothesis_id: UUID = field(default_factory=uuid4)
    statement: str = ""
    supporting_artifact_ids: list[UUID] = field(default_factory=list)
    contradicting_artifact_ids: list[UUID] = field(default_factory=list)
    notes: str | None = None


@dataclass(slots=True, kw_only=True)
class ToolHistoryEntry:
    """An auditable record of a tool or engine invocation."""

    execution_id: UUID = field(default_factory=uuid4)
    tool_name: str = ""
    tool_version: str | None = None
    status: str = "recorded"
    started_at: datetime | None = None
    completed_at: datetime | None = None
    input_reference: str | None = None
    output_reference: str | None = None
    error_message: str | None = None


@dataclass(slots=True, kw_only=True)
class TimelineEntry:
    """A timestamped observation linked to the case and optional source records."""

    event_id: UUID = field(default_factory=uuid4)
    occurred_at: datetime = field(default_factory=utc_now)
    event_type: str = ""
    summary: str = ""
    evidence_id: UUID | None = None
    artifact_id: UUID | None = None
    details: str | None = None


@dataclass(slots=True, kw_only=True)
class ConfidenceAssessment:
    """An explicit confidence assessment for any investigation subject."""

    subject_type: str
    subject_id: UUID
    score: float
    rationale: str | None = None
    assessed_by: str | None = None
    assessed_at: datetime = field(default_factory=utc_now)


@dataclass(slots=True, kw_only=True)
class RecommendationItem:
    """An actionable recommendation produced during an investigation."""

    recommendation_id: UUID = field(default_factory=uuid4)
    recommendation: str = ""
    priority: str = "medium"
    rationale: str | None = None
    source_reasoning_id: UUID | None = None


@dataclass(slots=True, kw_only=True)
class FinalReport:
    """The final report content and delivery metadata for an investigation."""

    report_id: UUID = field(default_factory=uuid4)
    title: str = ""
    content: str = ""
    format: str = "markdown"
    generated_at: datetime = field(default_factory=utc_now)
    storage_path: str | None = None


@dataclass(slots=True, kw_only=True)
class PluginOutput:
    """Structured output emitted by one plugin execution."""

    execution_id: UUID
    plugin_name: str
    plugin_version: str
    payload: Mapping[str, object] = field(default_factory=dict)
    evidence_id: UUID | None = None
    artifact_id: UUID | None = None
    produced_at: datetime = field(default_factory=utc_now)


@dataclass(slots=True, kw_only=True)
class AIMemoryEntry:
    """A scoped AI memory item with an optional traceable source reference."""

    memory_id: UUID = field(default_factory=uuid4)
    namespace: str = "case"
    key: str = ""
    value: str = ""
    source_reference: str | None = None
    created_at: datetime = field(default_factory=utc_now)


@dataclass(slots=True, kw_only=True)
class InvestigationState:
    """Complete engine-neutral snapshot of a cyber investigation.

    Every engine receives and returns this structure without requiring Flask,
    SQLAlchemy, plugin-framework, or AI-provider dependencies.
    """

    case: CaseMetadata
    evidence: list[EvidenceItem] = field(default_factory=list)
    artifacts: list[ArtifactItem] = field(default_factory=list)
    questions: list[InvestigationQuestion] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    tool_history: list[ToolHistoryEntry] = field(default_factory=list)
    timeline: list[TimelineEntry] = field(default_factory=list)
    confidence: list[ConfidenceAssessment] = field(default_factory=list)
    recommendations: list[RecommendationItem] = field(default_factory=list)
    final_report: FinalReport | None = None
    plugin_outputs: list[PluginOutput] = field(default_factory=list)
    ai_memory: list[AIMemoryEntry] = field(default_factory=list)
