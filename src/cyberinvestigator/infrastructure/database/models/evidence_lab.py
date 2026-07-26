"""Durable, tenant-scoped Digital Evidence Lab provenance."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from cyberinvestigator.infrastructure.database.base import IdentifiedRecord, utc_now


class EvidenceAnalysisRun(IdentifiedRecord):
    __tablename__ = "evidence_analysis_runs"
    __table_args__ = (
        Index("ix_evidence_analysis_evidence_started", "evidence_id", "created_at"),
        Index("ix_evidence_analysis_org_status", "organization_id", "status"),
    )

    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[UUID] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    evidence_id: Mapped[UUID] = mapped_column(ForeignKey("evidence.id", ondelete="CASCADE"), index=True)
    requested_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    analyzer: Mapped[str] = mapped_column(String(128), nullable=False)
    analyzer_version: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    evidence_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    integrity_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    module_manifest: Mapped[str | None] = mapped_column(Text)
    error_code: Mapped[str | None] = mapped_column(String(128))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ForensicFinding(IdentifiedRecord):
    __tablename__ = "forensic_findings"
    __table_args__ = (
        Index("ix_forensic_findings_evidence_type", "evidence_id", "finding_type"),
        Index("ix_forensic_findings_run_source", "analysis_run_id", "source"),
    )

    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[UUID] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    evidence_id: Mapped[UUID] = mapped_column(ForeignKey("evidence.id", ondelete="CASCADE"), index=True)
    analysis_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("evidence_analysis_runs.id", ondelete="CASCADE"), index=True
    )
    finding_type: Mapped[str] = mapped_column(String(128), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="static_analysis")
    value: Mapped[str] = mapped_column(Text, nullable=False)
    verified_observation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    confidence: Mapped[int | None] = mapped_column(Integer)


class CustodyEvent(IdentifiedRecord):
    """Append-only custody event; the application exposes no update/delete path."""

    __tablename__ = "custody_events"
    __table_args__ = (Index("ix_custody_events_evidence_created", "evidence_id", "created_at"),)

    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[UUID] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    evidence_id: Mapped[UUID] = mapped_column(ForeignKey("evidence.id", ondelete="CASCADE"), index=True)
    actor_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    evidence_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    storage_state: Mapped[str] = mapped_column(String(32), nullable=False, default="quarantined")
    details: Mapped[str | None] = mapped_column(Text)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
