"""Persistence for tenant-scoped ML registry, inference and model observations."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from cyberinvestigator.infrastructure.database.base import IdentifiedRecord, utc_now


class MLModel(IdentifiedRecord):
    __tablename__ = "ml_models"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", "version", name="uq_ml_model_org_name_version"),
        Index("ix_ml_models_org_status", "organization_id", "status"),
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    model_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="registered")
    feature_schema: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    validation_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    artifact_reference: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class MLInference(IdentifiedRecord):
    __tablename__ = "ml_inferences"
    __table_args__ = (
        Index("ix_ml_inferences_org_created", "organization_id", "created_at"),
        Index("ix_ml_inferences_model_status", "model_id", "status"),
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    model_id: Mapped[UUID | None] = mapped_column(ForeignKey("ml_models.id", ondelete="SET NULL"), nullable=True)
    case_id: Mapped[UUID | None] = mapped_column(ForeignKey("cases.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    input_summary: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    output: Mapped[str | None] = mapped_column(Text, nullable=True)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class MLModelObservation(IdentifiedRecord):
    __tablename__ = "ml_model_observations"
    __table_args__ = (Index("ix_ml_observations_model_created", "model_id", "created_at"),)
    model_id: Mapped[UUID] = mapped_column(ForeignKey("ml_models.id", ondelete="CASCADE"), nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    drift_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    measured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
