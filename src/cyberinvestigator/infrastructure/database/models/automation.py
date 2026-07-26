"""Tenant-scoped, auditable automation and approval records."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from cyberinvestigator.infrastructure.database.base import IdentifiedRecord, utc_now


class AutomationPlaybook(IdentifiedRecord):
    __tablename__ = "automation_playbooks"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_automation_playbook_org_name"),)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    trigger_type: Mapped[str] = mapped_column(String(64), nullable=False, default="manual")
    trigger_config: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    conditions: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class AutomationAction(IdentifiedRecord):
    __tablename__ = "automation_actions"
    __table_args__ = (Index("ix_automation_actions_playbook_position", "playbook_id", "position"),)
    playbook_id: Mapped[UUID] = mapped_column(ForeignKey("automation_playbooks.id", ondelete="CASCADE"), nullable=False)
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    configuration: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class AutomationExecution(IdentifiedRecord):
    __tablename__ = "automation_executions"
    __table_args__ = (
        Index("ix_automation_executions_org_started", "organization_id", "started_at"),
        Index("ix_automation_executions_status", "status", "started_at"),
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    playbook_id: Mapped[UUID] = mapped_column(
        ForeignKey("automation_playbooks.id", ondelete="RESTRICT"), nullable=False
    )
    case_id: Mapped[UUID | None] = mapped_column(ForeignKey("cases.id", ondelete="SET NULL"), nullable=True)
    trigger_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running")
    input_context: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    initiated_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class AutomationExecutionStep(IdentifiedRecord):
    __tablename__ = "automation_execution_steps"
    __table_args__ = (Index("ix_automation_execution_steps_execution", "execution_id", "position"),)
    execution_id: Mapped[UUID] = mapped_column(
        ForeignKey("automation_executions.id", ondelete="CASCADE"), nullable=False
    )
    action_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("automation_actions.id", ondelete="SET NULL"), nullable=True
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    output: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AutomationApproval(IdentifiedRecord):
    __tablename__ = "automation_approvals"
    __table_args__ = (Index("ix_automation_approvals_org_status", "organization_id", "status"),)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    execution_id: Mapped[UUID] = mapped_column(
        ForeignKey("automation_executions.id", ondelete="CASCADE"), nullable=False
    )
    step_id: Mapped[UUID] = mapped_column(
        ForeignKey("automation_execution_steps.id", ondelete="CASCADE"), nullable=False
    )
    requested_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    decision_comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
