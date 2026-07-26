"""Optional commercial deployment metadata, independent of core functionality."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from cyberinvestigator.infrastructure.database.base import IdentifiedRecord, utc_now


class OrganizationLicense(IdentifiedRecord):
    __tablename__ = "organization_licenses"
    __table_args__ = (UniqueConstraint("organization_id", name="uq_organization_license_org"),)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    edition: Mapped[str] = mapped_column(String(64), nullable=False, default="community")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="self_hosted")
    license_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class OrganizationFeatureFlag(IdentifiedRecord):
    __tablename__ = "organization_feature_flags"
    __table_args__ = (
        UniqueConstraint("organization_id", "key", name="uq_org_feature_flag"),
        Index("ix_org_feature_flags_org_enabled", "organization_id", "enabled"),
    )
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key: Mapped[str] = mapped_column(String(128), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    configuration: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    updated_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class MarketplaceListing(IdentifiedRecord):
    __tablename__ = "marketplace_listings"
    __table_args__ = (UniqueConstraint("plugin_identifier", "version", name="uq_marketplace_plugin_version"),)
    plugin_identifier: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    publisher: Mapped[str] = mapped_column(String(255), nullable=False)
    package_reference: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    signature_status: Mapped[str] = mapped_column(String(32), nullable=False, default="unverified")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft")
    created_by_user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)


class MarketplaceInstallation(IdentifiedRecord):
    __tablename__ = "marketplace_installations"
    __table_args__ = (UniqueConstraint("organization_id", "listing_id", name="uq_marketplace_installation"),)
    organization_id: Mapped[UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    listing_id: Mapped[UUID] = mapped_column(ForeignKey("marketplace_listings.id", ondelete="RESTRICT"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="requested")
    installed_by_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )
