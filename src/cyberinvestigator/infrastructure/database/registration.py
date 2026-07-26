"""Per-application SQLAlchemy registration."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from flask import Flask, g, has_request_context
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event

from cyberinvestigator.infrastructure.database.base import Base


def register_database(app: Flask) -> SQLAlchemy:
    """Create and attach a SQLAlchemy extension to one Flask application.

    The extension is deliberately instantiated here rather than as a module
    singleton, preventing configuration or engine state from leaking between
    application instances and test suites.
    """
    database = SQLAlchemy(model_class=Base)
    database.init_app(app)
    with app.app_context():
        import cyberinvestigator.infrastructure.database.models  # noqa: F401
        from cyberinvestigator.infrastructure.database.models import (
            AIConversation,
            AuditLog,
            AutomationApproval,
            AutomationExecution,
            AutomationPlaybook,
            Case,
            CustodyEvent,
            MarketplaceInstallation,
            MLInference,
            MLModel,
            MobileDevice,
            MobileOfflinePolicy,
            Notification,
            OrganizationFeatureFlag,
            OrganizationLicense,
            ProductFeedback,
            ProductReleasePlan,
            ProductRoadmapItem,
            ProductTelemetryPolicy,
        )

        engine = database.engine
        if engine.dialect.name == "sqlite":
            event.listen(engine, "connect", _enable_sqlite_foreign_keys)
        for model in (
            Case,
            AIConversation,
            AuditLog,
            Notification,
            AutomationPlaybook,
            AutomationExecution,
            AutomationApproval,
            MLModel,
            MLInference,
            MobileDevice,
            MobileOfflinePolicy,
            OrganizationLicense,
            OrganizationFeatureFlag,
            MarketplaceInstallation,
            ProductTelemetryPolicy,
            ProductFeedback,
            ProductRoadmapItem,
            ProductReleasePlan,
        ):
            if not event.contains(model, "before_insert", _assign_organization):
                event.listen(model, "before_insert", _assign_organization)
        for operation in ("before_update", "before_delete"):
            if not event.contains(CustodyEvent, operation, _prevent_custody_mutation):
                event.listen(CustodyEvent, operation, _prevent_custody_mutation)
        if bool(app.config.get("DATABASE_AUTO_CREATE_SCHEMA", True)):
            database.create_all()
    app.extensions["cyberinvestigator_database"] = database
    return database


def _enable_sqlite_foreign_keys(dbapi_connection: Any, _connection_record: Any) -> None:
    """Enable SQLite foreign-key enforcement for every newly opened connection."""
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


def _assign_organization(_mapper: Any, _connection: Any, target: Any) -> None:
    """Stamp compatibility or request tenant identity on new boundary records."""
    if getattr(target, "organization_id", None) is not None:
        return
    organization_id = getattr(g, "organization_id", None) if has_request_context() else None
    target.organization_id = (
        organization_id if isinstance(organization_id, UUID) else UUID("00000000-0000-0000-0000-000000000001")
    )


def _prevent_custody_mutation(_mapper: Any, _connection: Any, _target: Any) -> None:
    raise ValueError("Custody events are append-only and cannot be modified or deleted.")
