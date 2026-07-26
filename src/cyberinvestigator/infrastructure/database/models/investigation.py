"""Normalized SQLAlchemy models for investigation records and derived findings."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cyberinvestigator.infrastructure.database.base import IdentifiedRecord, utc_now

if TYPE_CHECKING:
    from cyberinvestigator.infrastructure.database.models.operations import (
        AIReasoning,
        PluginExecution,
        Recommendation,
        Report,
    )


class Case(IdentifiedRecord):
    """A top-level cyber investigation case."""

    __tablename__ = "cases"
    __table_args__ = (
        Index("ix_cases_owner_opened", "owner", "opened_at"),
        Index("ix_cases_organization_opened", "organization_id", "opened_at"),
        UniqueConstraint("organization_id", "case_number", name="uq_cases_organization_number"),
        Index("ix_cases_deleted_archived", "deleted_at", "archived_at"),
    )

    organization_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    case_number: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    owner_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    review_status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    reviewer_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    investigation_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, default="medium")
    priority: Mapped[str] = mapped_column(String(32), nullable=False, default="medium")
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tags: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    relationships: Mapped[str | None] = mapped_column(Text, nullable=True)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    evidence_items: Mapped[list[Evidence]] = relationship(back_populates="case", cascade="all, delete-orphan")
    timeline_events: Mapped[list[TimelineEvent]] = relationship(back_populates="case", cascade="all, delete-orphan")
    state_history: Mapped[list[InvestigationState]] = relationship(back_populates="case", cascade="all, delete-orphan")
    plugin_executions: Mapped[list[PluginExecution]] = relationship(back_populates="case", cascade="all, delete-orphan")
    ai_reasoning_records: Mapped[list[AIReasoning]] = relationship(back_populates="case", cascade="all, delete-orphan")
    recommendations: Mapped[list[Recommendation]] = relationship(back_populates="case", cascade="all, delete-orphan")
    reports: Mapped[list[Report]] = relationship(back_populates="case", cascade="all, delete-orphan")


class Evidence(IdentifiedRecord):
    """A source item acquired and preserved within a case."""

    __tablename__ = "evidence"
    __table_args__ = (
        UniqueConstraint("case_id", "evidence_number", name="uq_evidence_case_number"),
        CheckConstraint("size_bytes >= 0", name="ck_evidence_size_nonnegative"),
        Index("ix_evidence_case_sha256", "case_id", "sha256"),
        Index("ix_evidence_case_acquired", "case_id", "acquired_at"),
        Index("ix_evidence_case_analysis", "case_id", "analysis_status"),
        CheckConstraint("length(sha256) = 64", name="ck_evidence_sha256_length"),
    )

    case_id: Mapped[UUID] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    owner_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    evidence_number: Mapped[str] = mapped_column(String(64), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    storage_path: Mapped[str] = mapped_column(String(1024), unique=True, nullable=False)
    media_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    source_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    analysis_report: Mapped[str | None] = mapped_column(Text, nullable=True)
    analysis_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    analysis_status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    acquired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    case: Mapped[Case] = relationship(back_populates="evidence_items")
    artifacts: Mapped[list[Artifact]] = relationship(back_populates="evidence", cascade="all, delete-orphan")
    timeline_events: Mapped[list[TimelineEvent]] = relationship(back_populates="evidence")
    plugin_executions: Mapped[list[PluginExecution]] = relationship(back_populates="evidence")


class Artifact(IdentifiedRecord):
    """A discrete item extracted or identified from a source evidence record."""

    __tablename__ = "artifacts"
    __table_args__ = (
        Index("ix_artifacts_evidence_type", "evidence_id", "artifact_type"),
        Index("ix_artifacts_content_hash", "content_hash"),
    )

    evidence_id: Mapped[UUID] = mapped_column(ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False)
    analysis_run_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("evidence_analysis_runs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    parent_artifact_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True
    )
    artifact_type: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    source_location: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    evidence: Mapped[Evidence] = relationship(back_populates="artifacts")
    parent_artifact: Mapped[Artifact | None] = relationship(remote_side="Artifact.id", back_populates="child_artifacts")
    child_artifacts: Mapped[list[Artifact]] = relationship(back_populates="parent_artifact")
    timeline_events: Mapped[list[TimelineEvent]] = relationship(back_populates="artifact")
    plugin_executions: Mapped[list[PluginExecution]] = relationship(back_populates="artifact")


class TimelineEvent(IdentifiedRecord):
    """A time-bound event associated with a case and optional source records."""

    __tablename__ = "timeline_events"
    __table_args__ = (
        Index("ix_timeline_case_occurred", "case_id", "occurred_at"),
        Index("ix_timeline_case_type", "case_id", "event_type"),
    )

    case_id: Mapped[UUID] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    owner_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    evidence_id: Mapped[UUID | None] = mapped_column(ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True)
    artifact_id: Mapped[UUID | None] = mapped_column(ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    summary: Mapped[str] = mapped_column(String(1024), nullable=False)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)

    case: Mapped[Case] = relationship(back_populates="timeline_events")
    evidence: Mapped[Evidence | None] = relationship(back_populates="timeline_events")
    artifact: Mapped[Artifact | None] = relationship(back_populates="timeline_events")


class InvestigationState(IdentifiedRecord):
    """An immutable state transition in the lifecycle of a case."""

    __tablename__ = "investigation_states"
    __table_args__ = (Index("ix_investigation_state_case_changed", "case_id", "changed_at"),)

    case_id: Mapped[UUID] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    state: Mapped[str] = mapped_column(String(64), nullable=False)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    transition_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    case: Mapped[Case] = relationship(back_populates="state_history")


Timeline = TimelineEvent
"""Compatibility alias for the Timeline persistence model."""
