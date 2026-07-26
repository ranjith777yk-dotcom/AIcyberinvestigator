"""Tenant-scoped threat hunting and detection-engineering records."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from cyberinvestigator.infrastructure.database.base import IdentifiedRecord, utc_now


class ThreatHunt(IdentifiedRecord):
    __tablename__ = "threat_hunts"
    __table_args__ = (
        Index("ix_threat_hunts_org_status", "organization_id", "status"),
        Index("ix_threat_hunts_case_created", "case_id", "created_at"),
    )

    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[UUID] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    hypothesis: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft")
    owner_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class DetectionRule(IdentifiedRecord):
    __tablename__ = "detection_rules"
    __table_args__ = (
        UniqueConstraint("organization_id", "rule_key", "version", name="uq_detection_rule_version"),
        Index("ix_detection_rules_org_status", "organization_id", "status"),
    )

    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    rule_key: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="experimental")
    rule_format: Mapped[str] = mapped_column(String(32), nullable=False, default="sigma-json")
    definition: Mapped[str] = mapped_column(Text, nullable=False)
    attack_techniques: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class HuntIOCSearch(IdentifiedRecord):
    __tablename__ = "hunt_ioc_searches"
    __table_args__ = (Index("ix_hunt_ioc_searches_hunt_created", "hunt_id", "created_at"),)

    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    hunt_id: Mapped[UUID] = mapped_column(ForeignKey("threat_hunts.id", ondelete="CASCADE"), index=True)
    actor_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    indicator_type: Mapped[str] = mapped_column(String(32), nullable=False)
    indicator_value: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_matches: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    provider_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    provider_status: Mapped[str] = mapped_column(String(32), nullable=False, default="not_requested")


class HuntCorrelation(IdentifiedRecord):
    __tablename__ = "hunt_correlations"
    __table_args__ = (Index("ix_hunt_correlations_search_evidence", "search_id", "evidence_id"),)

    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    hunt_id: Mapped[UUID] = mapped_column(ForeignKey("threat_hunts.id", ondelete="CASCADE"), index=True)
    search_id: Mapped[UUID] = mapped_column(ForeignKey("hunt_ioc_searches.id", ondelete="CASCADE"), index=True)
    evidence_id: Mapped[UUID] = mapped_column(ForeignKey("evidence.id", ondelete="CASCADE"), index=True)
    indicator_type: Mapped[str] = mapped_column(String(32), nullable=False)
    indicator_value: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="evidence")


class DetectionAlert(IdentifiedRecord):
    __tablename__ = "detection_alerts"
    __table_args__ = (Index("ix_detection_alerts_hunt_status", "hunt_id", "status"),)

    organization_id: Mapped[UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    hunt_id: Mapped[UUID] = mapped_column(ForeignKey("threat_hunts.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[UUID] = mapped_column(ForeignKey("detection_rules.id", ondelete="RESTRICT"), index=True)
    evidence_id: Mapped[UUID] = mapped_column(ForeignKey("evidence.id", ondelete="CASCADE"), index=True)
    indicator_type: Mapped[str] = mapped_column(String(32), nullable=False)
    indicator_value: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="verified_evidence")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
