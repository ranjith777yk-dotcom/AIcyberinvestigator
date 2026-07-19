"""Shared SQLAlchemy declarative base and persistence primitives."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import DateTime, Uuid
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utc_now() -> datetime:
    """Return the current timezone-aware UTC timestamp for persistence defaults."""
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Base class shared by all CyberInvestigator persistence models."""


class IdentifiedRecord(Base):
    """Abstract base for records with UUID identity and creation metadata."""

    __abstract__ = True

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
