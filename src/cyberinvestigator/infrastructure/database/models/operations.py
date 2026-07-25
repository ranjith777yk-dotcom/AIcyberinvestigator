"""Normalized SQLAlchemy models for plugins, AI output, reports, and settings."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cyberinvestigator.infrastructure.database.base import IdentifiedRecord, utc_now

if TYPE_CHECKING:
    from cyberinvestigator.infrastructure.database.models.investigation import Artifact, Case, Evidence


class Plugin(IdentifiedRecord):
    """A versioned plugin definition available to the investigation platform."""

    __tablename__ = "plugins"
    __table_args__ = (UniqueConstraint("name", "version", name="uq_plugins_name_version"),)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_point: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)

    executions: Mapped[list[PluginExecution]] = relationship(back_populates="plugin")


class PluginExecution(IdentifiedRecord):
    """An auditable execution record for a plugin in a particular case."""

    __tablename__ = "plugin_executions"
    __table_args__ = (
        Index("ix_plugin_execution_case_started", "case_id", "started_at"),
        Index("ix_plugin_execution_status_started", "status", "started_at"),
    )

    case_id: Mapped[UUID] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    plugin_id: Mapped[UUID] = mapped_column(ForeignKey("plugins.id", ondelete="RESTRICT"), nullable=False)
    evidence_id: Mapped[UUID | None] = mapped_column(ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True)
    artifact_id: Mapped[UUID | None] = mapped_column(ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    output_location: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    case: Mapped[Case] = relationship(back_populates="plugin_executions")
    plugin: Mapped[Plugin] = relationship(back_populates="executions")
    evidence: Mapped[Evidence | None] = relationship(back_populates="plugin_executions")
    artifact: Mapped[Artifact | None] = relationship(back_populates="plugin_executions")
    ai_reasoning_records: Mapped[list[AIReasoning]] = relationship(back_populates="plugin_execution")


class AIReasoning(IdentifiedRecord):
    """A traceable AI-generated reasoning record for a case."""

    __tablename__ = "ai_reasoning"
    __table_args__ = (
        Index("ix_ai_reasoning_case_created", "case_id", "created_at"),
        Index("ix_ai_reasoning_provider_model", "provider", "model"),
    )

    case_id: Mapped[UUID] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    owner_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")
    plugin_execution_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("plugin_executions.id", ondelete="SET NULL"), nullable=True
    )
    provider: Mapped[str] = mapped_column(String(128), nullable=False)
    model: Mapped[str] = mapped_column(String(255), nullable=False)
    prompt_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reasoning: Mapped[str] = mapped_column(Text, nullable=False)
    input_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)

    case: Mapped[Case] = relationship(back_populates="ai_reasoning_records")
    plugin_execution: Mapped[PluginExecution | None] = relationship(back_populates="ai_reasoning_records")
    recommendations: Mapped[list[Recommendation]] = relationship(
        back_populates="ai_reasoning", cascade="all, delete-orphan"
    )


class Recommendation(IdentifiedRecord):
    """An actionable recommendation grounded in one AI reasoning record."""

    __tablename__ = "recommendations"
    __table_args__ = (
        Index("ix_recommendations_case_created", "case_id", "created_at"),
        Index("ix_recommendations_case_status", "case_id", "status"),
    )

    case_id: Mapped[UUID] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    ai_reasoning_id: Mapped[UUID] = mapped_column(ForeignKey("ai_reasoning.id", ondelete="CASCADE"), nullable=False)
    priority: Mapped[str] = mapped_column(String(32), nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")

    case: Mapped[Case] = relationship(back_populates="recommendations")
    ai_reasoning: Mapped[AIReasoning] = relationship(back_populates="recommendations")


class Report(IdentifiedRecord):
    """A generated report retained as a versioned case deliverable."""

    __tablename__ = "reports"
    __table_args__ = (
        UniqueConstraint("case_id", "report_type", "version", name="uq_reports_case_type_version"),
        Index("ix_reports_case_created", "case_id", "created_at"),
        Index("ix_reports_generated", "generated_at"),
    )

    case_id: Mapped[UUID] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    owner_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft")
    report_type: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    storage_path: Mapped[str] = mapped_column(String(1024), unique=True, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    case: Mapped[Case] = relationship(back_populates="reports")


class AIConversation(IdentifiedRecord):
    """Persisted, user-isolated AI conversation turn."""

    __tablename__ = "ai_conversations"
    __table_args__ = (Index("ix_ai_conversations_owner_created", "owner_user_id", "created_at"),)

    owner_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    conversation_id: Mapped[UUID] = mapped_column(default=uuid4, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="New chat")
    created_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    case_id: Mapped[UUID | None] = mapped_column(ForeignKey("cases.id", ondelete="SET NULL"), nullable=True)
    user_message: Mapped[str] = mapped_column(Text, nullable=False)
    assistant_message: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class Upload(IdentifiedRecord):
    """Ownership record for a user upload, including chat attachments."""

    __tablename__ = "uploads"
    __table_args__ = (Index("ix_uploads_owner_created", "owner_user_id", "created_at"),)

    owner_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    created_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    case_id: Mapped[UUID | None] = mapped_column(ForeignKey("cases.id", ondelete="SET NULL"), nullable=True)
    evidence_id: Mapped[UUID | None] = mapped_column(ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True)
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    storage_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="stored")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class Setting(IdentifiedRecord):
    """A namespaced, typed platform setting stored as an atomic key-value record."""

    __tablename__ = "settings"
    __table_args__ = (
        UniqueConstraint("namespace", "key", name="uq_settings_namespace_key"),
        Index("ix_settings_namespace_updated", "namespace", "updated_at"),
    )

    namespace: Mapped[str] = mapped_column(String(128), nullable=False, default="application")
    key: Mapped[str] = mapped_column(String(255), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    value_type: Mapped[str] = mapped_column(String(32), nullable=False, default="string")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )
