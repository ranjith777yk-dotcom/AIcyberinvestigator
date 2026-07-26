"""Version 1 API blueprint."""

from __future__ import annotations

import csv
import hashlib
import html
import json
import re
import secrets
import shutil
import stat
import time
import tomllib
import zipfile
from datetime import datetime, timedelta
from io import BytesIO, StringIO
from pathlib import Path
from urllib.parse import urlparse
from uuid import UUID, uuid4

from flask import (
    Blueprint,
    Response,
    current_app,
    g,
    has_request_context,
    jsonify,
    request,
    stream_with_context,
)
from flask import (
    session as flask_session,
)
from sqlalchemy import func, select, text

from cyberinvestigator.api.v1.openapi import build_openapi_spec
from cyberinvestigator.application.dto import CaseCreateRequest, CaseUpdateRequest, EvidenceAddRequest
from cyberinvestigator.application.ports.ai_provider import AIRequest
from cyberinvestigator.application.ports.intelligence_sharing import UnavailableIntelligenceSharingAdapter
from cyberinvestigator.application.ports.sandbox import UnavailableSandboxAdapter
from cyberinvestigator.application.ports.threat_intelligence import normalize_indicator
from cyberinvestigator.infrastructure.ai import AIProviderUnavailable, build_ai_registry
from cyberinvestigator.infrastructure.ai import messages as ai_messages
from cyberinvestigator.infrastructure.ai_management import hydrate_ai_config
from cyberinvestigator.infrastructure.cache import SecureTTLCache
from cyberinvestigator.infrastructure.database.base import utc_now
from cyberinvestigator.infrastructure.database.models import (
    AIConversation,
    AIReasoning,
    Artifact,
    AuditLog,
    AutomationAction,
    AutomationApproval,
    AutomationExecution,
    AutomationExecutionStep,
    AutomationPlaybook,
    Case,
    CaseReview,
    CaseTeamMember,
    CollaborationTask,
    CustodyEvent,
    DetectionAlert,
    DetectionRule,
    DiscussionComment,
    DiscussionThread,
    Evidence,
    EvidenceAnalysisRun,
    ForensicFinding,
    HuntCorrelation,
    HuntIOCSearch,
    IntelligenceIndicator,
    IntelligenceObject,
    IntelligenceRelationship,
    MarketplaceInstallation,
    MarketplaceListing,
    MLInference,
    MLModel,
    MobileDevice,
    MobileOfflinePolicy,
    Notification,
    Organization,
    OrganizationFeatureFlag,
    OrganizationInvitation,
    OrganizationLicense,
    OrganizationMembership,
    OrganizationQuota,
    OrganizationSetting,
    Permission,
    Plugin,
    PluginExecution,
    ProductFeedback,
    ProductReleasePlan,
    ProductRoadmapItem,
    ProductTelemetryPolicy,
    Recommendation,
    Report,
    Role,
    RolePermission,
    SecurityAlert,
    Setting,
    ThreatHunt,
    TimelineEvent,
    Upload,
    User,
    UserSession,
)
from cyberinvestigator.infrastructure.evidence_lab import EvidenceLabAnalyzer
from cyberinvestigator.infrastructure.governance import (
    CLASSIFICATION_LEVELS,
    DEFAULT_GOVERNANCE_POLICY,
    decoded_setting,
)
from cyberinvestigator.infrastructure.integrations import ConnectorCategory, ConnectorHealth, ConnectorSyncResult
from cyberinvestigator.infrastructure.observability import redact_text
from cyberinvestigator.infrastructure.plugins.loader import PluginLoadError
from cyberinvestigator.infrastructure.plugins.registry import PluginMetadata
from cyberinvestigator.infrastructure.security.credential_vault import CredentialVault, CredentialVaultUnavailable
from cyberinvestigator.infrastructure.security.plugin_runtime_security import PLUGIN_RUNTIME_PERMISSIONS
from cyberinvestigator.infrastructure.security.web_security import hash_password, require_role
from cyberinvestigator.infrastructure.storage_management import StorageOperationError
from cyberinvestigator.shared.exceptions import (
    CaseManagementError,
    EvidenceManagementError,
)

api_v1_blueprint = Blueprint("api_v1", __name__, url_prefix="/api/v1")
"""Blueprint namespace for stable version 1 API endpoints."""


@api_v1_blueprint.after_request
def api_version_headers(response):  # type: ignore[no-untyped-def]
    """Expose the stable major contract on every v1 response."""
    response.headers.setdefault("API-Version", "v1")
    response.headers.setdefault("Vary", "Cookie")
    return response


def _db():
    return current_app.extensions["cyberinvestigator_database"]


def _features():
    return current_app.extensions["cyberinvestigator_features"]


def _storage_manager():
    return current_app.extensions["cyberinvestigator_storage_manager"]


def _deployment_inspector():
    return current_app.extensions["cyberinvestigator_deployment_inspector"]


def _quality_inspector():
    return current_app.extensions["cyberinvestigator_quality_inspector"]


def _performance_inspector():
    return current_app.extensions["cyberinvestigator_performance_inspector"]


def _governance_inspector():
    return current_app.extensions["cyberinvestigator_governance_inspector"]


def _runtime_cache() -> SecureTTLCache:
    """Return the configured cache while preserving direct-blueprint test compatibility."""
    return current_app.extensions.setdefault("cyberinvestigator_cache", SecureTTLCache())


def _case_service():
    return _features().cases.service(_db().session, current_app.logger, _current_organization_id())


def _evidence_service():
    return _features().evidence.service(_db().session, current_app.logger)


def _timeline_service():
    return _features().timeline.service(_db().session, current_app.logger)


def _json_error(message: str, status: int = 400):
    return jsonify({"error": message}), status


def _uuid(value: str, field: str = "id") -> UUID:
    try:
        return UUID(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be a valid UUID.") from error


def _iso(value):
    return value.isoformat() if value is not None else None


def _json_list(value) -> list:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return value
    try:
        decoded = json.loads(value)
        return decoded if isinstance(decoded, list) else []
    except (TypeError, json.JSONDecodeError):
        return [item.strip() for item in str(value).split(",") if item.strip()]


def _stored_json(value) -> object | None:
    if not value:
        return None
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return {"raw": str(value)}


def _request_cache(name: str) -> dict[object, object]:
    cache = getattr(g, name, None)
    if cache is None:
        cache = {}
        setattr(g, name, cache)
    return cache


def _cached_model(model, model_id):
    if model_id is None:
        return None
    cache = _request_cache(f"_cache_{model.__tablename__}")
    if model_id not in cache:
        cache[model_id] = _db().session.get(model, model_id)
    return cache[model_id]


def _case_json(case, *, include_related: bool = True):
    case_id = case.id
    attachments = []
    history = []
    if include_related:
        try:
            session = _db().session
            attachments = [
                _evidence_json(item)
                for item in session.scalars(
                    select(Evidence)
                    .where(Evidence.case_id == case_id, Evidence.deleted_at.is_(None))
                    .order_by(Evidence.acquired_at.desc())
                    .limit(8)
                )
            ]
            history = [
                _timeline_json(item)
                for item in session.scalars(
                    select(TimelineEvent)
                    .where(TimelineEvent.case_id == case_id)
                    .order_by(TimelineEvent.occurred_at.desc())
                    .limit(8)
                )
            ]
        except RuntimeError as error:
            current_app.logger.debug("Case related records could not be loaded for %s: %s", case_id, error)
    return {
        "id": str(case.id),
        "case_number": case.case_number,
        "title": case.title,
        "description": case.description,
        "severity": case.severity,
        "priority": getattr(case, "priority", None) or case.severity,
        "owner": getattr(case, "owner", None),
        "owner_user_id": str(case.owner_user_id) if getattr(case, "owner_user_id", None) else None,
        "created_by": str(case.created_by_user_id) if getattr(case, "created_by_user_id", None) else None,
        "created_at": _iso(case.created_at),
        "updated_at": _iso(case.updated_at),
        "tags": _json_list(getattr(case, "tags", None)),
        "notes": _json_list(getattr(case, "notes", None)),
        "relationships": _json_list(getattr(case, "relationships", None)),
        "review_status": case.review_status,
        "reviewer_user_id": str(case.reviewer_user_id) if case.reviewer_user_id else None,
        "investigation_notes": case.investigation_notes,
        "attachments": attachments,
        "history": history,
        "opened_at": _iso(case.opened_at),
        "closed_at": _iso(case.closed_at),
        "archived_at": _iso(case.archived_at),
        "deleted_at": _iso(case.deleted_at),
        "status": "deleted"
        if case.deleted_at
        else "archived"
        if case.archived_at
        else "closed"
        if case.closed_at
        else "active",
    }


def _evidence_json(evidence):
    return {
        "id": str(evidence.id),
        "case_id": str(evidence.case_id),
        "owner_user_id": str(evidence.owner_user_id) if evidence.owner_user_id else None,
        "created_by": str(evidence.created_by_user_id) if evidence.created_by_user_id else None,
        "created_at": _iso(evidence.created_at),
        "updated_at": _iso(evidence.updated_at),
        "status": evidence.status,
        "evidence_number": evidence.evidence_number,
        "original_filename": evidence.original_filename,
        "storage_path": evidence.storage_path,
        "media_type": evidence.media_type,
        "size_bytes": evidence.size_bytes,
        "sha256": evidence.sha256,
        "source_description": evidence.source_description,
        "analysis_status": getattr(evidence, "analysis_status", "pending"),
        "analysis_summary": getattr(evidence, "analysis_summary", None),
        "analysis_report": _stored_json(getattr(evidence, "analysis_report", None)),
        "acquired_at": _iso(evidence.acquired_at),
        "deleted_at": _iso(evidence.deleted_at),
    }


def _timeline_json(event):
    case = _cached_model(Case, event.case_id)
    evidence = _cached_model(Evidence, event.evidence_id)
    event_type = event.event_type or ""
    return {
        "id": str(event.id),
        "case_id": str(event.case_id),
        "owner_user_id": str(event.owner_user_id) if event.owner_user_id else None,
        "created_by": str(event.created_by_user_id) if event.created_by_user_id else None,
        "created_at": _iso(event.created_at),
        "updated_at": _iso(event.updated_at),
        "status": event.status,
        "case_number": case.case_number if case else None,
        "evidence_id": str(event.evidence_id) if event.evidence_id else None,
        "evidence_number": evidence.evidence_number if evidence else None,
        "artifact_id": str(event.artifact_id) if event.artifact_id else None,
        "occurred_at": _iso(event.occurred_at),
        "event_type": event_type,
        "group": event_type.split(".", 1)[0] if "." in event_type else event_type,
        "threat_weight": 0,
        "threat_level": "unassessed",
        "certainty": "confirmed",
        "summary": event.summary,
        "details": event.details,
    }


def _report_json(report):
    return {
        "id": str(report.id),
        "case_id": str(report.case_id),
        "owner_user_id": str(report.owner_user_id) if report.owner_user_id else None,
        "created_by": str(report.created_by_user_id) if report.created_by_user_id else None,
        "created_at": _iso(report.created_at),
        "updated_at": _iso(report.updated_at),
        "status": report.status,
        "report_type": report.report_type,
        "version": report.version,
        "title": report.title,
        "storage_path": report.storage_path,
        "generated_at": _iso(report.generated_at),
    }


def _user_json(user: User) -> dict[str, object]:
    return {
        "id": str(user.id),
        "username": user.username,
        "email": user.email,
        "role": user.role.name,
        "status": user.status,
        "created_at": _iso(user.created_at),
        "updated_at": _iso(user.updated_at),
        "last_login_at": _iso(user.last_login_at),
        "failed_login_count": user.failed_login_count,
        "locked_until": _iso(user.locked_until),
    }


def _audit_log_json(record: AuditLog) -> dict[str, object]:
    return {
        "id": str(record.id),
        "title": record.action,
        "event": record.action,
        "message": f"{record.result} - {record.affected_object or 'platform'}",
        "user": record.username,
        "role": record.role,
        "result": record.result,
        "ip_address": record.ip_address,
        "user_agent": record.user_agent,
        "affected_object": record.affected_object,
        "reason": record.reason,
        "created_at": _iso(record.created_at),
    }


def _security_alert_json(alert: SecurityAlert) -> dict[str, object]:
    return {
        "id": str(alert.id),
        "level": alert.level,
        "category": alert.category,
        "title": alert.title,
        "message": alert.message,
        "status": alert.status,
        "score": alert.score,
        "confidence": alert.confidence,
        "created_at": _iso(alert.created_at),
    }


def _short_text(value: str | None, fallback: str = "") -> str:
    text = (value or "").strip()
    return text if text else fallback


def _current_user_role() -> str:
    return str(getattr(getattr(g, "current_user", None), "role", "user"))


def _current_username() -> str:
    return str(getattr(getattr(g, "current_user", None), "username", "user"))


def _current_user_id() -> UUID | None:
    try:
        return UUID(str(getattr(getattr(g, "current_user", None), "user_id", "")))
    except (TypeError, ValueError):
        return None


def _current_organization_id() -> UUID:
    value = getattr(g, "organization_id", None)
    return value if isinstance(value, UUID) else UUID("00000000-0000-0000-0000-000000000001")


def _automation_audit(action: str, result: str, affected_object: str, reason: str | None = None) -> None:
    """Persist automation lifecycle events alongside the platform security audit."""
    _db().session.add(
        AuditLog(
            user_id=_current_user_id(),
            organization_id=_current_organization_id(),
            username=_current_username(),
            role=_current_user_role(),
            action=action,
            result=result,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            affected_object=affected_object,
            reason=reason,
        )
    )


def _automation_json(playbook: AutomationPlaybook) -> dict[str, object]:
    actions = (
        _db()
        .session.scalars(
            select(AutomationAction)
            .where(AutomationAction.playbook_id == playbook.id)
            .order_by(AutomationAction.position)
        )
        .all()
    )
    return {
        "id": str(playbook.id),
        "name": playbook.name,
        "description": playbook.description,
        "trigger_type": playbook.trigger_type,
        "trigger_config": json.loads(playbook.trigger_config),
        "conditions": json.loads(playbook.conditions),
        "enabled": playbook.enabled,
        "version": playbook.version,
        "created_at": _iso(playbook.created_at),
        "updated_at": _iso(playbook.updated_at),
        "actions": [
            {
                "id": str(item.id),
                "name": item.name,
                "type": item.action_type,
                "configuration": json.loads(item.configuration),
                "requires_approval": item.requires_approval,
                "position": item.position,
            }
            for item in actions
        ],
    }


def _execution_json(execution: AutomationExecution) -> dict[str, object]:
    steps = (
        _db()
        .session.scalars(
            select(AutomationExecutionStep)
            .where(AutomationExecutionStep.execution_id == execution.id)
            .order_by(AutomationExecutionStep.position)
        )
        .all()
    )
    return {
        "id": str(execution.id),
        "playbook_id": str(execution.playbook_id),
        "case_id": str(execution.case_id) if execution.case_id else None,
        "trigger_type": execution.trigger_type,
        "status": execution.status,
        "input_context": json.loads(execution.input_context),
        "started_at": _iso(execution.started_at),
        "completed_at": _iso(execution.completed_at),
        "steps": [
            {
                "id": str(step.id),
                "position": step.position,
                "status": step.status,
                "output": json.loads(step.output) if step.output else None,
                "error_message": step.error_message,
                "started_at": _iso(step.started_at),
                "completed_at": _iso(step.completed_at),
            }
            for step in steps
        ],
    }


def _conditions_match(conditions: list[object], context: dict[str, object]) -> bool:
    """Evaluate the intentionally small, deterministic playbook condition DSL."""
    for condition in conditions:
        if not isinstance(condition, dict):
            return False
        field, operator = str(condition.get("field") or ""), str(condition.get("operator") or "equals")
        value: object = context
        for part in field.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        expected = condition.get("value")
        if operator == "equals" and value != expected:
            return False
        if operator == "exists" and bool(value) != bool(expected if expected is not None else True):
            return False
        if operator not in {"equals", "exists"}:
            return False
    return True


def _analytics_audit(action: str, result: str, affected: str, reason: str | None = None) -> None:
    _db().session.add(
        AuditLog(
            user_id=_current_user_id(),
            organization_id=_current_organization_id(),
            username=_current_username(),
            role=_current_user_role(),
            action=action,
            result=result,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            affected_object=affected,
            reason=reason,
        )
    )


def _model_json(model: MLModel) -> dict[str, object]:
    return {
        "id": str(model.id),
        "name": model.name,
        "version": model.version,
        "model_type": model.model_type,
        "status": model.status,
        "feature_schema": json.loads(model.feature_schema),
        "validation_summary": json.loads(model.validation_summary) if model.validation_summary else None,
        "artifact_reference": model.artifact_reference,
        "created_at": _iso(model.created_at),
        "updated_at": _iso(model.updated_at),
    }


@api_v1_blueprint.get("/analytics/workspace")
def analytics_workspace():
    org = _current_organization_id()
    session = _db().session
    models = session.scalars(
        select(MLModel).where(MLModel.organization_id == org).order_by(MLModel.updated_at.desc())
    ).all()
    inferences = session.scalars(
        select(MLInference).where(MLInference.organization_id == org).order_by(MLInference.created_at.desc()).limit(50)
    ).all()
    evidence = session.scalars(
        select(Evidence)
        .join(Case)
        .where(Case.organization_id == org, Case.deleted_at.is_(None), Evidence.deleted_at.is_(None))
    ).all()
    media: dict[str, int] = {}
    for item in evidence:
        media[item.media_type or "unknown"] = media.get(item.media_type or "unknown", 0) + 1
    trends = session.execute(
        select(func.date(Case.opened_at), func.count())
        .where(Case.organization_id == org, Case.deleted_at.is_(None))
        .group_by(func.date(Case.opened_at))
        .order_by(func.date(Case.opened_at).desc())
        .limit(30)
    ).all()
    return jsonify(
        {
            "models": [_model_json(item) for item in models],
            "inferences": [
                {
                    "id": str(item.id),
                    "model_id": str(item.model_id) if item.model_id else None,
                    "case_id": str(item.case_id) if item.case_id else None,
                    "status": item.status,
                    "output": json.loads(item.output) if item.output else None,
                    "explanation": json.loads(item.explanation) if item.explanation else None,
                    "error_message": item.error_message,
                    "created_at": _iso(item.created_at),
                }
                for item in inferences
            ],
            "insights": {
                "evidence_count": len(evidence),
                "evidence_by_media_type": media,
                "case_trend": [{"date": str(date), "count": count} for date, count in trends],
                "data_source": "persisted investigation and evidence metadata",
            },
            "notice": "Analytics recommendations are not verified investigative findings.",
        }
    )


@api_v1_blueprint.post("/analytics/models")
def register_ml_model():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name") or "").strip()
    version = str(payload.get("version") or "").strip()
    model_type = str(payload.get("model_type") or "").strip()
    if (
        not name
        or not version
        or model_type not in {"anomaly_detection", "clustering", "prioritization", "trend_analysis"}
    ):
        return _json_error("name, version, and a supported model_type are required.")
    model = MLModel(
        organization_id=_current_organization_id(),
        name=name[:255],
        version=version[:64],
        model_type=model_type,
        status="registered",
        feature_schema=json.dumps(payload.get("feature_schema") or []),
        validation_summary=json.dumps(payload["validation_summary"])
        if isinstance(payload.get("validation_summary"), dict)
        else None,
        artifact_reference=str(payload.get("artifact_reference") or "")[:1024] or None,
        created_by_user_id=_current_user_id(),
    )
    _db().session.add(model)
    _analytics_audit("ml.model.registered", "completed", str(model.id))
    _db().session.commit()
    return jsonify(_model_json(model)), 201


@api_v1_blueprint.post("/analytics/models/<model_id>/infer")
def infer_ml_model(model_id: str):
    try:
        model_id_value = _uuid(model_id, "model_id")
    except ValueError as error:
        return _json_error(str(error))
    model = _db().session.get(MLModel, model_id_value)
    if model is None or model.organization_id != _current_organization_id():
        return _json_error("Model not found.", 404)
    payload = request.get_json(silent=True) or {}
    case_id = _uuid(payload["case_id"], "case_id") if payload.get("case_id") else None
    inference = MLInference(
        organization_id=model.organization_id,
        model_id=model.id,
        case_id=case_id,
        status="unavailable",
        input_summary=json.dumps({"case_id": str(case_id) if case_id else None, "source": "persisted metadata only"}),
        requested_by_user_id=_current_user_id(),
    )
    if model.status != "active" or not model.artifact_reference:
        inference.error_message = "No validated active inference artifact is available for this model."
    else:
        inference.error_message = "The configured model artifact cannot be executed by this deployment."
    _db().session.add(inference)
    _analytics_audit("ml.inference.requested", "unavailable", str(inference.id), inference.error_message)
    _db().session.commit()
    return jsonify(
        {
            "id": str(inference.id),
            "status": inference.status,
            "error_message": inference.error_message,
            "notice": "No prediction was produced.",
        }
    ), 202


@api_v1_blueprint.post("/analytics/metadata-anomaly-analysis")
def metadata_anomaly_analysis():
    """Transparent robust-size outlier analysis; never represented as a trained-model prediction."""
    org = _current_organization_id()
    rows = (
        _db()
        .session.scalars(
            select(Evidence)
            .join(Case)
            .where(Case.organization_id == org, Case.deleted_at.is_(None), Evidence.deleted_at.is_(None))
        )
        .all()
    )
    values = sorted(item.size_bytes for item in rows)
    inference = MLInference(
        organization_id=org,
        model_id=None,
        case_id=None,
        status="completed",
        input_summary=json.dumps({"evidence_count": len(rows), "features": ["size_bytes"]}),
        requested_by_user_id=_current_user_id(),
    )
    if len(values) < 4:
        inference.status = "unavailable"
        inference.error_message = (
            "At least four persisted evidence records are required for robust metadata outlier analysis."
        )
    else:
        mid = len(values) // 2
        median = (values[mid - 1] + values[mid]) / 2 if len(values) % 2 == 0 else values[mid]
        deviations = sorted(abs(value - median) for value in values)
        mad = deviations[mid] or 0
        anomalies = (
            []
            if mad == 0
            else [
                {
                    "evidence_id": str(item.id),
                    "size_bytes": item.size_bytes,
                    "modified_z_score": round(0.6745 * (item.size_bytes - median) / mad, 4),
                }
                for item in rows
                if abs(0.6745 * (item.size_bytes - median) / mad) > 3.5
            ]
        )
        inference.output = json.dumps(
            {"method": "median_absolute_deviation", "anomalies": anomalies, "sample_count": len(values)}
        )
        inference.explanation = json.dumps(
            {
                "features": ["evidence.size_bytes"],
                "threshold": "absolute modified z-score > 3.5",
                "median": median,
                "mad": mad,
                "interpretation": "Metadata outliers require investigator verification.",
            }
        )
    _db().session.add(inference)
    _analytics_audit("ml.metadata_analysis.requested", inference.status, str(inference.id), inference.error_message)
    _db().session.commit()
    return jsonify(
        {
            "id": str(inference.id),
            "status": inference.status,
            "output": json.loads(inference.output) if inference.output else None,
            "explanation": json.loads(inference.explanation) if inference.explanation else None,
            "error_message": inference.error_message,
            "notice": "Results are analytical signals, not verified findings.",
        }
    ), 202


def _mobile_audit(action: str, result: str, affected: str, reason: str | None = None) -> None:
    _db().session.add(
        AuditLog(
            user_id=_current_user_id(),
            organization_id=_current_organization_id(),
            username=_current_username(),
            role=_current_user_role(),
            action=action,
            result=result,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            affected_object=affected,
            reason=reason,
        )
    )


def _mobile_device_json(item: MobileDevice) -> dict[str, object]:
    return {
        "id": str(item.id),
        "display_name": item.display_name,
        "platform": item.platform,
        "status": item.status,
        "biometric_capable": item.biometric_capable,
        "last_sync_at": _iso(item.last_sync_at),
        "last_seen_at": _iso(item.last_seen_at),
        "updated_at": _iso(item.updated_at),
    }


@api_v1_blueprint.get("/mobile/companion")
def mobile_companion_snapshot():
    """Small, access-scoped payload for the companion; it is live server data."""
    org = _current_organization_id()
    user_id = _current_user_id()
    session = _db().session
    case_statement = (
        select(Case)
        .where(Case.organization_id == org, Case.deleted_at.is_(None))
        .order_by(Case.updated_at.desc())
        .limit(50)
    )
    if not _is_admin():
        case_statement = case_statement.where(Case.owner_user_id == user_id)
    cases = session.scalars(case_statement).all()
    tasks = session.scalars(
        select(CollaborationTask)
        .where(CollaborationTask.organization_id == org, CollaborationTask.assignee_user_id == user_id)
        .order_by(CollaborationTask.updated_at.desc())
        .limit(50)
    ).all()
    notifications = session.scalars(
        select(Notification)
        .where(
            Notification.organization_id == org, Notification.owner_user_id == user_id, Notification.archived.is_(False)
        )
        .order_by(Notification.created_at.desc())
        .limit(50)
    ).all()
    approvals = session.scalars(
        select(AutomationApproval)
        .where(AutomationApproval.organization_id == org, AutomationApproval.status == "pending")
        .order_by(AutomationApproval.created_at.desc())
        .limit(50)
    ).all()
    reports = session.scalars(
        select(Report)
        .where(Report.case_id.in_([item.id for item in cases]) if cases else text("0=1"))
        .order_by(Report.generated_at.desc())
        .limit(50)
    ).all()
    policy = session.scalar(select(MobileOfflinePolicy).where(MobileOfflinePolicy.organization_id == org))
    return jsonify(
        {
            "source": "live_platform",
            "synchronized_at": _iso(utc_now()),
            "cases": [
                {
                    "id": str(item.id),
                    "case_number": item.case_number,
                    "title": item.title,
                    "status": item.status,
                    "priority": item.priority,
                    "updated_at": _iso(item.updated_at),
                }
                for item in cases
            ],
            "tasks": [_task_json(item) for item in tasks],
            "notifications": [_notification_json(item) for item in notifications],
            "approvals": [
                {
                    "id": str(item.id),
                    "execution_id": str(item.execution_id),
                    "step_id": str(item.step_id),
                    "created_at": _iso(item.created_at),
                }
                for item in approvals
            ],
            "reports": [_report_json(item) for item in reports],
            "offline_policy": {
                "enabled": policy.enabled,
                "max_age_hours": policy.max_age_hours,
                "allow_evidence_metadata": policy.allow_evidence_metadata,
            }
            if policy
            else {"enabled": False, "reason": "No organization offline policy is configured."},
        }
    )


@api_v1_blueprint.post("/mobile/devices")
def register_mobile_device():
    payload = request.get_json(silent=True) or {}
    device_key = str(payload.get("device_key") or "").strip()
    platform = str(payload.get("platform") or "").lower()
    if not device_key or len(device_key) > 128 or platform not in {"ios", "android", "web"}:
        return _json_error("A device_key and supported platform are required.")
    session = _db().session
    org = _current_organization_id()
    user_id = _current_user_id()
    device = session.scalar(
        select(MobileDevice).where(
            MobileDevice.organization_id == org, MobileDevice.user_id == user_id, MobileDevice.device_key == device_key
        )
    )
    if device is None:
        device = MobileDevice(
            organization_id=org,
            user_id=user_id,
            device_key=device_key,
            display_name=str(payload.get("display_name") or platform.title())[:255],
            platform=platform,
            biometric_capable=bool(payload.get("biometric_capable", False)),
        )
        session.add(device)
    else:
        device.display_name = str(payload.get("display_name") or device.display_name)[:255]
        device.biometric_capable = bool(payload.get("biometric_capable", device.biometric_capable))
        device.status = "trusted"
    device.last_seen_at = utc_now()
    _mobile_audit(
        "mobile.device.registered",
        "completed",
        str(device.id),
        "Biometric capability is device-declared; server session authentication remains required.",
    )
    session.commit()
    return jsonify(_mobile_device_json(device)), 201


@api_v1_blueprint.post("/mobile/devices/<device_id>/sync")
def synchronize_mobile_device(device_id: str):
    try:
        device_id_value = _uuid(device_id, "device_id")
    except ValueError as error:
        return _json_error(str(error))
    device = _db().session.get(MobileDevice, device_id_value)
    if (
        device is None
        or device.organization_id != _current_organization_id()
        or device.user_id != _current_user_id()
        or device.status != "trusted"
    ):
        return _json_error("Trusted device not found.", 404)
    device.last_seen_at = utc_now()
    device.last_sync_at = utc_now()
    _mobile_audit("mobile.sync.completed", "completed", str(device.id))
    _db().session.commit()
    snapshot = mobile_companion_snapshot().get_json()
    snapshot["sync"] = {
        "status": "completed",
        "device": _mobile_device_json(device),
        "data_state": "live payload delivered; local encryption and retention are enforced by the companion client.",
    }
    return jsonify(snapshot)


@api_v1_blueprint.patch("/mobile/offline-policy")
def update_mobile_offline_policy():
    payload = request.get_json(silent=True) or {}
    enabled = bool(payload.get("enabled", False))
    max_age = payload.get("max_age_hours", 24)
    if not isinstance(max_age, int) or max_age < 1 or max_age > 720:
        return _json_error("max_age_hours must be between 1 and 720.")
    session = _db().session
    policy = session.scalar(
        select(MobileOfflinePolicy).where(MobileOfflinePolicy.organization_id == _current_organization_id())
    )
    if policy is None:
        policy = MobileOfflinePolicy(organization_id=_current_organization_id())
        session.add(policy)
    policy.enabled = enabled
    policy.max_age_hours = max_age
    policy.allow_evidence_metadata = bool(payload.get("allow_evidence_metadata", False))
    policy.updated_by_user_id = _current_user_id()
    _mobile_audit("mobile.offline_policy.updated", "completed", str(policy.id))
    session.commit()
    return jsonify(
        {
            "enabled": policy.enabled,
            "max_age_hours": policy.max_age_hours,
            "allow_evidence_metadata": policy.allow_evidence_metadata,
            "updated_at": _iso(policy.updated_at),
        }
    )


def _commercial_audit(action: str, result: str, affected: str, reason: str | None = None) -> None:
    _db().session.add(
        AuditLog(
            user_id=_current_user_id(),
            organization_id=_current_organization_id(),
            username=_current_username(),
            role=_current_user_role(),
            action=action,
            result=result,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            affected_object=affected,
            reason=reason,
        )
    )


@api_v1_blueprint.get("/commercial/workspace")
def commercial_workspace():
    org = _current_organization_id()
    session = _db().session
    license_record = session.scalar(select(OrganizationLicense).where(OrganizationLicense.organization_id == org))
    flags = session.scalars(
        select(OrganizationFeatureFlag)
        .where(OrganizationFeatureFlag.organization_id == org)
        .order_by(OrganizationFeatureFlag.key)
    ).all()
    quotas = session.scalars(
        select(OrganizationQuota).where(OrganizationQuota.organization_id == org).order_by(OrganizationQuota.resource)
    ).all()
    listings = session.scalars(
        select(MarketplaceListing)
        .where(MarketplaceListing.status == "published")
        .order_by(MarketplaceListing.created_at.desc())
    ).all()
    installs = {
        item.listing_id: item
        for item in session.scalars(
            select(MarketplaceInstallation).where(MarketplaceInstallation.organization_id == org)
        ).all()
    }
    registry = current_app.extensions.get("cyberinvestigator_plugin_registry")
    available = (
        {
            item.identifier: {"name": item.name, "version": item.version, "category": item.category}
            for item in registry.list_metadata()
        }
        if registry
        else {}
    )
    return jsonify(
        {
            "commercial_mode": "optional",
            "billing": {
                "provider": "unavailable",
                "status": "No billing adapter is configured; no billing data or invoices are available.",
            },
            "license": {
                "edition": license_record.edition,
                "status": license_record.status,
                "reference": license_record.license_reference,
                "expires_at": _iso(license_record.expires_at),
            }
            if license_record
            else {"edition": "community", "status": "self_hosted", "detail": "No commercial license is configured."},
            "feature_flags": [
                {
                    "key": item.key,
                    "enabled": item.enabled,
                    "configuration": json.loads(item.configuration),
                    "updated_at": _iso(item.updated_at),
                }
                for item in flags
            ],
            "quotas": [
                {"resource": item.resource, "limit": item.limit_value, "enabled": item.enabled} for item in quotas
            ],
            "marketplace": [
                {
                    "id": str(item.id),
                    "plugin_identifier": item.plugin_identifier,
                    "version": item.version,
                    "title": item.title,
                    "description": item.description,
                    "publisher": item.publisher,
                    "signature_status": item.signature_status,
                    "runtime_available": item.plugin_identifier in available,
                    "installation_status": installs[item.id].status if item.id in installs else None,
                }
                for item in listings
            ],
            "runtime_plugins": available,
        }
    )


@api_v1_blueprint.put("/commercial/license")
def update_commercial_license():
    payload = request.get_json(silent=True) or {}
    edition = str(payload.get("edition") or "community").lower()
    status = str(payload.get("status") or "self_hosted").lower()
    if edition not in {"community", "enterprise"} or status not in {"self_hosted", "active", "expired", "disabled"}:
        return _json_error("Unsupported license edition or status.")
    session = _db().session
    record = session.scalar(
        select(OrganizationLicense).where(OrganizationLicense.organization_id == _current_organization_id())
    )
    if record is None:
        record = OrganizationLicense(organization_id=_current_organization_id())
        session.add(record)
    record.edition = edition
    record.status = status
    record.license_reference = str(payload.get("license_reference") or "")[:255] or None
    record.updated_by_user_id = _current_user_id()
    _commercial_audit("commercial.license.updated", "completed", str(record.id))
    session.commit()
    return jsonify({"edition": record.edition, "status": record.status, "reference": record.license_reference})


@api_v1_blueprint.put("/commercial/feature-flags/<key>")
def update_commercial_feature_flag(key: str):
    if not re.fullmatch(r"[a-z0-9_.-]{1,128}", key):
        return _json_error("Invalid feature flag key.")
    payload = request.get_json(silent=True) or {}
    config = payload.get("configuration") or {}
    if not isinstance(config, dict):
        return _json_error("configuration must be an object.")
    session = _db().session
    flag = session.scalar(
        select(OrganizationFeatureFlag).where(
            OrganizationFeatureFlag.organization_id == _current_organization_id(), OrganizationFeatureFlag.key == key
        )
    )
    if flag is None:
        flag = OrganizationFeatureFlag(organization_id=_current_organization_id(), key=key)
        session.add(flag)
    flag.enabled = bool(payload.get("enabled", False))
    flag.configuration = json.dumps(config)
    flag.updated_by_user_id = _current_user_id()
    _commercial_audit("commercial.feature_flag.updated", "completed", str(flag.id))
    session.commit()
    return jsonify({"key": flag.key, "enabled": flag.enabled, "configuration": config})


@api_v1_blueprint.post("/commercial/marketplace/listings")
def create_marketplace_listing():
    payload = request.get_json(silent=True) or {}
    identifier = str(payload.get("plugin_identifier") or "").strip()
    version = str(payload.get("version") or "").strip()
    signature = str(payload.get("signature_status") or "unverified")
    if not identifier or not version or signature not in {"verified", "unverified", "rejected"}:
        return _json_error("plugin_identifier, version, and valid signature_status are required.")
    listing = MarketplaceListing(
        plugin_identifier=identifier[:255],
        version=version[:64],
        title=str(payload.get("title") or identifier)[:255],
        description=str(payload.get("description") or "")[:4000] or None,
        publisher=str(payload.get("publisher") or "Unknown publisher")[:255],
        package_reference=str(payload.get("package_reference") or "")[:1024] or None,
        signature_status=signature,
        status="published" if signature == "verified" else "draft",
        created_by_user_id=_current_user_id(),
    )
    _db().session.add(listing)
    _commercial_audit(
        "marketplace.listing.created", "completed", str(listing.id), "Only verified listings may be published."
    )
    _db().session.commit()
    return jsonify({"id": str(listing.id), "status": listing.status, "signature_status": listing.signature_status}), 201


@api_v1_blueprint.post("/commercial/marketplace/listings/<listing_id>/install")
def request_marketplace_installation(listing_id: str):
    try:
        listing_id_value = _uuid(listing_id, "listing_id")
    except ValueError as error:
        return _json_error(str(error))
    listing = _db().session.get(MarketplaceListing, listing_id_value)
    if listing is None or listing.status != "published" or listing.signature_status != "verified":
        return _json_error("Only published, verified marketplace packages may be installed.", 409)
    registry = current_app.extensions.get("cyberinvestigator_plugin_registry")
    if registry is None or not registry.contains(listing.plugin_identifier):
        return _json_error("Package is verified but unavailable in this deployment's plugin runtime.", 409)
    session = _db().session
    install = session.scalar(
        select(MarketplaceInstallation).where(
            MarketplaceInstallation.organization_id == _current_organization_id(),
            MarketplaceInstallation.listing_id == listing.id,
        )
    )
    if install is None:
        install = MarketplaceInstallation(
            organization_id=_current_organization_id(),
            listing_id=listing.id,
            status="installed",
            installed_by_user_id=_current_user_id(),
        )
        session.add(install)
    else:
        install.status = "installed"
        install.installed_by_user_id = _current_user_id()
    _commercial_audit(
        "marketplace.installation.completed",
        "completed",
        str(install.id),
        f"Runtime plugin: {listing.plugin_identifier}",
    )
    session.commit()
    return jsonify({"id": str(install.id), "status": install.status, "plugin_identifier": listing.plugin_identifier})


def _product_audit(action: str, affected: str) -> None:
    _db().session.add(
        AuditLog(
            user_id=_current_user_id(),
            organization_id=_current_organization_id(),
            username=_current_username(),
            role=_current_user_role(),
            action=action,
            result="completed",
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            affected_object=affected,
        )
    )


@api_v1_blueprint.get("/product/workspace")
def product_workspace():
    org = _current_organization_id()
    s = _db().session
    policy = s.scalar(select(ProductTelemetryPolicy).where(ProductTelemetryPolicy.organization_id == org))
    feedback = s.scalars(
        select(ProductFeedback)
        .where(ProductFeedback.organization_id == org)
        .order_by(ProductFeedback.created_at.desc())
        .limit(100)
    ).all()
    roadmap = s.scalars(
        select(ProductRoadmapItem)
        .where(ProductRoadmapItem.organization_id == org)
        .order_by(ProductRoadmapItem.updated_at.desc())
    ).all()
    releases = s.scalars(
        select(ProductReleasePlan)
        .where(ProductReleasePlan.organization_id == org)
        .order_by(ProductReleasePlan.updated_at.desc())
    ).all()
    telemetry = current_app.extensions["cyberinvestigator_telemetry"].snapshot() if policy and policy.enabled else None
    return jsonify(
        {
            "telemetry": {
                "enabled": bool(policy and policy.enabled),
                "measured": telemetry,
                "detail": "Current-process operational telemetry only."
                if telemetry
                else "Product telemetry is disabled by organization policy.",
            },
            "feedback": [
                {
                    "id": str(x.id),
                    "category": x.category,
                    "body": x.body,
                    "status": x.status,
                    "created_at": _iso(x.created_at),
                }
                for x in feedback
            ],
            "roadmap": [
                {
                    "id": str(x.id),
                    "title": x.title,
                    "description": x.description,
                    "status": x.status,
                    "priority": x.priority,
                    "updated_at": _iso(x.updated_at),
                }
                for x in roadmap
            ],
            "releases": [
                {
                    "id": str(x.id),
                    "name": x.name,
                    "status": x.status,
                    "notes": x.notes,
                    "updated_at": _iso(x.updated_at),
                }
                for x in releases
            ],
            "ai_insights": {
                "status": "unavailable",
                "detail": "No dedicated AI product-insight request has been configured; no recommendation was generated.",
            },
        }
    )


@api_v1_blueprint.put("/product/telemetry")
def update_product_telemetry():
    body = request.get_json(silent=True) or {}
    s = _db().session
    policy = s.scalar(
        select(ProductTelemetryPolicy).where(ProductTelemetryPolicy.organization_id == _current_organization_id())
    )
    if policy is None:
        policy = ProductTelemetryPolicy(organization_id=_current_organization_id())
        s.add(policy)
    policy.enabled = bool(body.get("enabled", False))
    policy.updated_by_user_id = _current_user_id()
    _product_audit("product.telemetry.updated", str(policy.id))
    s.commit()
    return jsonify({"enabled": policy.enabled, "updated_at": _iso(policy.updated_at)})


@api_v1_blueprint.post("/product/feedback")
def create_product_feedback():
    body = request.get_json(silent=True) or {}
    text_value = str(body.get("body") or "").strip()
    category = str(body.get("category") or "general")
    if not text_value or len(text_value) > 4000:
        return _json_error("Feedback body is required and limited to 4000 characters.")
    item = ProductFeedback(
        organization_id=_current_organization_id(),
        author_user_id=_current_user_id(),
        category=category[:64],
        body=text_value,
    )
    _db().session.add(item)
    _product_audit("product.feedback.created", str(item.id))
    _db().session.commit()
    return jsonify({"id": str(item.id), "status": item.status}), 201


@api_v1_blueprint.post("/product/roadmap")
def create_product_roadmap_item():
    body = request.get_json(silent=True) or {}
    title = str(body.get("title") or "").strip()
    if not title:
        return _json_error("Roadmap title is required.")
    item = ProductRoadmapItem(
        organization_id=_current_organization_id(),
        title=title[:255],
        description=str(body.get("description") or "")[:4000] or None,
        status=str(body.get("status") or "planned")[:32],
        priority=str(body.get("priority") or "medium")[:32],
        created_by_user_id=_current_user_id(),
    )
    _db().session.add(item)
    _product_audit("product.roadmap.created", str(item.id))
    _db().session.commit()
    return jsonify({"id": str(item.id), "status": item.status}), 201


@api_v1_blueprint.post("/product/releases")
def create_product_release_plan():
    body = request.get_json(silent=True) or {}
    name = str(body.get("name") or "").strip()
    if not name:
        return _json_error("Release name is required.")
    item = ProductReleasePlan(
        organization_id=_current_organization_id(),
        name=name[:255],
        status="draft",
        notes=str(body.get("notes") or "")[:4000] or None,
        created_by_user_id=_current_user_id(),
    )
    _db().session.add(item)
    _product_audit("product.release.created", str(item.id))
    _db().session.commit()
    return jsonify({"id": str(item.id), "status": item.status}), 201


@api_v1_blueprint.get("/automation/workspace")
def automation_workspace():
    organization_id = _current_organization_id()
    playbooks = (
        _db()
        .session.scalars(
            select(AutomationPlaybook)
            .where(AutomationPlaybook.organization_id == organization_id)
            .order_by(AutomationPlaybook.updated_at.desc())
        )
        .all()
    )
    executions = (
        _db()
        .session.scalars(
            select(AutomationExecution)
            .where(AutomationExecution.organization_id == organization_id)
            .order_by(AutomationExecution.started_at.desc())
            .limit(50)
        )
        .all()
    )
    approvals = (
        _db()
        .session.scalars(
            select(AutomationApproval)
            .where(AutomationApproval.organization_id == organization_id, AutomationApproval.status == "pending")
            .order_by(AutomationApproval.created_at.desc())
        )
        .all()
    )
    return jsonify(
        {
            "playbooks": [_automation_json(item) for item in playbooks],
            "executions": [_execution_json(item) for item in executions],
            "pending_approvals": [
                {
                    "id": str(item.id),
                    "execution_id": str(item.execution_id),
                    "step_id": str(item.step_id),
                    "created_at": _iso(item.created_at),
                }
                for item in approvals
            ],
            "supported_actions": [
                {"type": "notification", "privileged": False},
                {"type": "plugin_operation", "privileged": True},
            ],
            "integration_status": "available through configured plugins; unavailable operations are recorded as failed",
        }
    )


@api_v1_blueprint.post("/automation/playbooks")
def create_automation_playbook():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name") or "").strip()
    trigger_type = str(payload.get("trigger_type") or "manual").strip()
    actions = payload.get("actions") or []
    if not name or len(name) > 255 or not isinstance(actions, list) or not actions:
        return _json_error("name and at least one action are required.")
    if trigger_type not in {"manual", "case.created", "evidence.added", "intelligence.enriched"}:
        return _json_error("Unsupported trigger type.")
    if any(
        not isinstance(item, dict) or item.get("type") not in {"notification", "plugin_operation"} for item in actions
    ):
        return _json_error("Unsupported automation action.")
    playbook = AutomationPlaybook(
        organization_id=_current_organization_id(),
        name=name,
        description=str(payload.get("description") or "")[:4000],
        trigger_type=trigger_type,
        trigger_config=json.dumps(payload.get("trigger_config") or {}),
        conditions=json.dumps(payload.get("conditions") or []),
        enabled=bool(payload.get("enabled", False)),
        created_by_user_id=_current_user_id(),
    )
    _db().session.add(playbook)
    _db().session.flush()
    for position, action in enumerate(actions, start=1):
        _db().session.add(
            AutomationAction(
                playbook_id=playbook.id,
                position=position,
                name=str(action.get("name") or action["type"])[:255],
                action_type=action["type"],
                configuration=json.dumps(action.get("configuration") or {}),
                requires_approval=bool(action.get("requires_approval", action["type"] == "plugin_operation")),
            )
        )
    _automation_audit("automation.playbook.created", "completed", str(playbook.id))
    _db().session.commit()
    return jsonify(_automation_json(playbook)), 201


@api_v1_blueprint.post("/automation/playbooks/<playbook_id>/execute")
def execute_automation_playbook(playbook_id: str):
    try:
        playbook_id_value = _uuid(playbook_id, "playbook_id")
    except ValueError as error:
        return _json_error(str(error))
    playbook = _db().session.get(AutomationPlaybook, playbook_id_value)
    if playbook is None or playbook.organization_id != _current_organization_id():
        return _json_error("Playbook not found.", 404)
    payload = request.get_json(silent=True) or {}
    context = payload.get("context") or {}
    if not isinstance(context, dict):
        return _json_error("context must be an object.")
    execution = AutomationExecution(
        organization_id=playbook.organization_id,
        playbook_id=playbook.id,
        case_id=_uuid(payload["case_id"], "case_id") if payload.get("case_id") else None,
        trigger_type=str(payload.get("trigger_type") or "manual"),
        input_context=json.dumps(context),
        initiated_by_user_id=_current_user_id(),
    )
    _db().session.add(execution)
    _db().session.flush()
    if not _conditions_match(json.loads(playbook.conditions), context):
        execution.status = "skipped"
        execution.completed_at = utc_now()
        _automation_audit(
            "automation.execution.skipped",
            "skipped",
            str(execution.id),
            "Playbook conditions did not match the supplied event context.",
        )
        _db().session.commit()
        return jsonify(_execution_json(execution)), 202
    blocked = False
    for action in _db().session.scalars(
        select(AutomationAction).where(AutomationAction.playbook_id == playbook.id).order_by(AutomationAction.position)
    ):
        if blocked:
            _db().session.add(
                AutomationExecutionStep(
                    execution_id=execution.id, action_id=action.id, position=action.position, status="not_started"
                )
            )
            continue
        step = AutomationExecutionStep(
            execution_id=execution.id, action_id=action.id, position=action.position, status="running"
        )
        _db().session.add(step)
        _db().session.flush()
        if action.requires_approval:
            step.status = "pending_approval"
            _db().session.add(
                AutomationApproval(
                    organization_id=playbook.organization_id,
                    execution_id=execution.id,
                    step_id=step.id,
                    requested_by_user_id=_current_user_id(),
                )
            )
            blocked = True
        elif action.action_type == "notification":
            config = json.loads(action.configuration)
            _db().session.add(
                Notification(
                    user_id=_current_user_id(),
                    owner_user_id=_current_user_id(),
                    created_by_user_id=_current_user_id(),
                    organization_id=playbook.organization_id,
                    title=str(config.get("title") or "Automation completed")[:255],
                    message=str(config.get("message") or f"Playbook {playbook.name} completed an action.")[:4000],
                    category="automation",
                    priority=str(config.get("priority") or "info"),
                    read=False,
                    archived=False,
                    pinned=False,
                )
            )
            step.status = "completed"
            step.output = json.dumps({"delivery": "notification_recorded"})
            step.completed_at = utc_now()
        else:
            step.status = "failed"
            step.error_message = (
                "Plugin operation was not dispatched: no approved plugin execution binding is configured."
            )
            step.completed_at = utc_now()
            execution.status = "failed"
            blocked = True
    if execution.status != "failed":
        execution.status = "pending_approval" if blocked else "completed"
    if execution.status == "completed":
        execution.completed_at = utc_now()
    _automation_audit("automation.execution.started", execution.status, str(execution.id))
    _db().session.commit()
    return jsonify(_execution_json(execution)), 202


@api_v1_blueprint.post("/automation/approvals/<approval_id>/decision")
def decide_automation_approval(approval_id: str):
    try:
        approval_id_value = _uuid(approval_id, "approval_id")
    except ValueError as error:
        return _json_error(str(error))
    approval = _db().session.get(AutomationApproval, approval_id_value)
    if approval is None or approval.organization_id != _current_organization_id():
        return _json_error("Approval not found.", 404)
    payload = request.get_json(silent=True) or {}
    decision = str(payload.get("decision") or "").lower()
    if approval.status != "pending" or decision not in {"approved", "rejected"}:
        return _json_error("A pending approval and approved or rejected decision are required.")
    approval.status = decision
    approval.decision_comment = str(payload.get("comment") or "")[:4000]
    approval.decided_by_user_id = _current_user_id()
    approval.decided_at = utc_now()
    step = _db().session.get(AutomationExecutionStep, approval.step_id)
    execution = _db().session.get(AutomationExecution, approval.execution_id)
    step.status = "failed" if decision == "approved" else "rejected"
    step.error_message = (
        "Approved operation was not dispatched: no approved plugin execution binding is configured."
        if decision == "approved"
        else "Operation rejected by approver."
    )
    step.completed_at = utc_now()
    execution.status = "failed" if decision == "approved" else "rejected"
    execution.completed_at = utc_now()
    _automation_audit("automation.approval." + decision, execution.status, str(execution.id), approval.decision_comment)
    _db().session.commit()
    return jsonify(_execution_json(execution))


def _is_admin() -> bool:
    return _current_user_role() == "admin"


def _owned_case_ids() -> set[UUID]:
    if _is_admin():
        return set(
            _db().session.scalars(
                select(Case.id).where(
                    Case.deleted_at.is_(None),
                    Case.organization_id == _current_organization_id(),
                )
            )
        )
    user_id = _current_user_id()
    if user_id is None:
        return set()
    owned = set(
        _db().session.scalars(
            select(Case.id).where(
                Case.deleted_at.is_(None),
                Case.organization_id == _current_organization_id(),
                (Case.owner_user_id == user_id) | (Case.reviewer_user_id == user_id),
            )
        )
    )
    assigned = set(
        _db().session.scalars(
            select(CaseTeamMember.case_id).where(
                CaseTeamMember.organization_id == _current_organization_id(),
                CaseTeamMember.user_id == user_id,
                CaseTeamMember.status == "active",
            )
        )
    )
    return owned | assigned


def _case_accessible(case_id: UUID) -> bool:
    case = _db().session.get(Case, case_id)
    if case is None or case.organization_id != _current_organization_id():
        return False
    if _is_admin():
        return True
    user_id = _current_user_id()
    if user_id is None:
        return False
    if user_id in {case.owner_user_id, case.reviewer_user_id}:
        return True
    return (
        _db().session.scalar(
            select(CaseTeamMember.id).where(
                CaseTeamMember.organization_id == _current_organization_id(),
                CaseTeamMember.case_id == case_id,
                CaseTeamMember.user_id == user_id,
                CaseTeamMember.status == "active",
            )
        )
        is not None
    )


def _record_case_audit(action: str, case: Case, *, reason: str | None = None) -> None:
    """Persist one semantic, actor-attributed case lifecycle audit event."""

    _db().session.add(
        AuditLog(
            user_id=_current_user_id(),
            username=_current_username(),
            role=_current_user_role(),
            action=action,
            result="success",
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            affected_object=f"case:{case.id}",
            reason=reason or f"{case.case_number} · {case.title}",
        )
    )
    _db().session.commit()


def _record_evidence_audit(
    action: str,
    evidence: Evidence,
    *,
    actor_id: UUID | None = None,
    username: str | None = None,
    role: str | None = None,
    result: str = "success",
    reason: str | None = None,
) -> None:
    """Persist an actor-attributed custody or analysis audit event."""

    case = _db().session.get(Case, evidence.case_id)
    _db().session.add(
        AuditLog(
            organization_id=case.organization_id if case else _current_organization_id(),
            user_id=actor_id if actor_id is not None else _current_user_id(),
            username=username or _current_username(),
            role=role or _current_user_role(),
            action=action,
            result=result,
            ip_address=request.remote_addr if has_request_context() else None,
            user_agent=request.headers.get("User-Agent") if has_request_context() else None,
            affected_object=f"evidence:{evidence.id}",
            reason=reason or f"{evidence.evidence_number} · case:{evidence.case_id}",
        )
    )
    _db().session.commit()


def _append_custody_event(
    evidence: Evidence,
    event_type: str,
    *,
    storage_state: str = "quarantined",
    details: str | None = None,
    actor_id: UUID | None = None,
) -> None:
    """Append custody provenance without exposing a mutation endpoint."""
    case = _db().session.get(Case, evidence.case_id)
    _db().session.add(
        CustodyEvent(
            organization_id=case.organization_id if case and case.organization_id else _current_organization_id(),
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            actor_user_id=actor_id if actor_id is not None else _current_user_id(),
            event_type=event_type,
            evidence_sha256=evidence.sha256,
            storage_state=storage_state,
            details=details,
        )
    )


def _record_intelligence_audit(case: Case, *, result: str, reason: str) -> None:
    """Record enrichment without logging indicators or provider credentials."""
    _db().session.add(
        AuditLog(
            user_id=_current_user_id(),
            username=_current_username(),
            role=_current_user_role(),
            action="threat_intelligence.enriched",
            result=result,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            affected_object=f"case:{case.id}",
            reason=reason,
        )
    )
    _db().session.commit()


def _record_timeline_audit(event: TimelineEvent, *, action: str = "timeline.manual_event.created") -> None:
    """Record actor and provenance for a manual timeline mutation."""
    _db().session.add(
        AuditLog(
            user_id=_current_user_id(),
            username=_current_username(),
            role=_current_user_role(),
            action=action,
            result="success",
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            affected_object=f"timeline_event:{event.id}",
            reason=f"case:{event.case_id} · event_type:{event.event_type}",
        )
    )
    _db().session.commit()


def _record_report_audit(report: Report, action: str, *, reason: str | None = None) -> None:
    """Record report lifecycle activity without embedding report contents."""
    _db().session.add(
        AuditLog(
            user_id=_current_user_id(),
            username=_current_username(),
            role=_current_user_role(),
            action=action,
            result="success",
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            affected_object=f"report:{report.id}",
            reason=reason or f"case:{report.case_id} · {report.report_type} v{report.version}",
        )
    )
    _db().session.commit()


def _record_account_audit(action: str, affected_object: str, *, reason: str | None = None) -> None:
    _db().session.add(
        AuditLog(
            user_id=_current_user_id(),
            username=_current_username(),
            role=_current_user_role(),
            action=action,
            result="success",
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            affected_object=affected_object,
            reason=reason,
        )
    )
    _db().session.commit()


def _stamp_owned(record, *, owner_user_id: UUID | None = None) -> None:
    """Apply immutable creator and current owner metadata to a new record."""
    actor = _current_user_id()
    record.owner_user_id = owner_user_id or actor
    record.created_by_user_id = actor
    record.updated_at = utc_now()


def _stamp_case_children(case_id: UUID) -> None:
    """Stamp service-created evidence/timeline records from their parent case."""
    session = _db().session
    case = session.get(Case, case_id)
    if case is None:
        return
    for model in (Evidence, TimelineEvent, Report, AIReasoning):
        for record in session.scalars(select(model).where(model.case_id == case_id, model.owner_user_id.is_(None))):
            _stamp_owned(record, owner_user_id=case.owner_user_id)
    session.commit()


def _save_conversation(
    user_message: str, assistant_message: str, case_id: object = None, conversation_id: object = None
) -> AIConversation:
    parsed_case_id = None
    try:
        parsed_case_id = _uuid(str(case_id), "case_id") if case_id else None
    except ValueError:
        parsed_case_id = None
    if parsed_case_id and not _case_accessible(parsed_case_id):
        parsed_case_id = None
    try:
        thread_id = _uuid(str(conversation_id), "conversation_id") if conversation_id else uuid4()
    except ValueError:
        thread_id = uuid4()
    existing = _db().session.scalar(
        select(AIConversation)
        .where(
            AIConversation.conversation_id == thread_id,
            AIConversation.organization_id == _current_organization_id(),
            AIConversation.owner_user_id == _current_user_id(),
        )
        .limit(1)
    )
    title = existing.title if existing else (user_message.strip()[:80] or "New chat")
    record = AIConversation(
        owner_user_id=_current_user_id(),
        organization_id=_current_organization_id(),
        conversation_id=thread_id,
        title=title,
        created_by_user_id=_current_user_id(),
        case_id=parsed_case_id,
        user_message=user_message,
        assistant_message=assistant_message,
    )
    _db().session.add(record)
    _db().session.commit()
    return record


def _forbidden(message: str = "You do not have access to this resource."):
    return jsonify({"error": message}), 403


def _normalize_text(value, *, limit: int = 10_000) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if len(text) > limit:
        raise ValueError(f"Value must not exceed {limit} characters.")
    return text or None


def _normalize_list(value, *, limit: int = 50) -> str:
    if value in (None, ""):
        return "[]"
    raw_items = value if isinstance(value, list) else str(value).split(",")
    items = []
    for item in raw_items:
        text = str(item).strip()
        if text and text not in items:
            items.append(text[:128])
        if len(items) >= limit:
            break
    return json.dumps(items)


def _apply_case_workspace_fields(case_id: UUID, data: dict[str, object]) -> Case:
    case = _db().session.get(Case, case_id)
    if case is None:
        raise ValueError("Case was not found after save.")
    if "priority" in data:
        priority = str(data.get("priority") or "medium").strip().lower()
        if priority not in {"critical", "high", "medium", "low", "informational"}:
            raise ValueError("Case priority must be critical, high, medium, low, or informational.")
        case.priority = priority
    actor = _current_user_id()
    if case.created_by_user_id is None:
        case.created_by_user_id = actor
    if case.owner_user_id is None:
        case.owner_user_id = actor
    if "owner" in data and _is_admin():
        owner_name = _normalize_text(data.get("owner"), limit=255)
        owner = _db().session.scalar(select(User).where(func.lower(User.username) == str(owner_name or "").lower()))
        if owner_name and owner is None:
            raise ValueError("Assigned owner was not found.")
        case.owner = owner.username if owner else None
        case.owner_user_id = owner.id if owner else None
    elif not _is_admin():
        case.owner = _current_username()
        case.owner_user_id = actor
    case.updated_at = utc_now()
    if "tags" in data:
        case.tags = _normalize_list(data.get("tags"))
    if "notes" in data:
        notes = data.get("notes")
        case.notes = (
            _normalize_list(notes)
            if isinstance(notes, list)
            else json.dumps([_normalize_text(notes)] if _normalize_text(notes) else [])
        )
    if "relationships" in data:
        case.relationships = _normalize_list(data.get("relationships"))
    _db().session.commit()
    return case


def _page(items: list[dict], *, total: int) -> dict:
    page = max(int(request.args.get("page", 1)), 1)
    per_page = min(max(int(request.args.get("per_page", 10)), 1), 100)
    start = (page - 1) * per_page
    return {
        "items": items[start : start + per_page],
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page,
        },
    }


def _query_text() -> str:
    return request.args.get("q", "").strip().lower()


def _sort_key(default: str, allowed: set[str]) -> str:
    sort = request.args.get("sort", default)
    return sort if sort in allowed else default


def _direction() -> str:
    return "asc" if request.args.get("direction", "desc") == "asc" else "desc"


def _setting_value(namespace: str, key: str, default: str = "") -> str:
    setting = _db().session.scalar(select(Setting).where(Setting.namespace == namespace, Setting.key == key))
    return setting.value if setting else default


def _set_setting(namespace: str, key: str, value: str, value_type: str = "string") -> Setting:
    session = _db().session
    setting = session.scalar(select(Setting).where(Setting.namespace == namespace, Setting.key == key))
    if setting is None:
        setting = Setting(namespace=namespace, key=key, value=value, value_type=value_type)
        session.add(setting)
    else:
        setting.value = value
        setting.value_type = value_type
    session.commit()
    return setting


def _invalidate_dashboard_cache() -> None:
    _runtime_cache().invalidate()


def _ai_runtime():
    registry = current_app.extensions.get("cyberinvestigator_ai_registry")
    if registry is not None and hasattr(registry, "configure_failover"):
        _configure_ai_failover(registry)
    return (
        registry,
        current_app.extensions.get("cyberinvestigator_investigation_assistant"),
        current_app.extensions.get("cyberinvestigator_analysis_engine"),
    )


def _provider_status() -> dict[str, object]:
    registry, _, _ = _ai_runtime()
    provider = str(current_app.config.get("AI_PROVIDER", "ollama"))
    if registry is None:
        return {
            "provider": provider,
            "available": False,
            "configured": False,
            "model": str(current_app.config.get("AI_MODEL") or "qwen3:8b"),
            "message": "AI runtime is unavailable.",
        }
    status = registry.status(provider)
    if current_app.config.get("AI_ENABLED") and not status.available:
        try:
            selected = registry.select(provider)
        except AIProviderUnavailable:
            pass
        else:
            selected_name = (
                selected.provider_name.value
                if hasattr(selected.provider_name, "value")
                else str(selected.provider_name)
            )
            status = registry.status(selected_name)
    test_live_ai_disabled = bool(current_app.config.get("TESTING")) and not bool(current_app.config.get("AI_ENABLED"))
    return {
        "provider": status.provider,
        "available": bool(status.available and not test_live_ai_disabled),
        "configured": status.configured,
        "model": status.model,
        "message": status.message,
        "endpoint": status.endpoint,
        "installed_models": list(status.installed_models),
        "health_source": status.health_source,
        "checked_at": status.checked_at,
    }


def _provider_status_payload() -> dict[str, object]:
    registry, _, _ = _ai_runtime()
    statuses = registry.all_statuses() if registry is not None and hasattr(registry, "all_statuses") else {}
    return {
        name: {
            "provider": status.provider,
            "available": status.available,
            "configured": status.configured,
            "model": status.model,
            "message": status.message,
            "endpoint": status.endpoint,
            "installed_models": list(status.installed_models),
            "health_source": status.health_source,
            "checked_at": status.checked_at,
        }
        for name, status in statuses.items()
    }


AI_WORKLOADS = {
    "chat.general",
    "chat.cybersecurity",
    "chat.investigation",
    "evidence.analysis",
    "timeline.summary",
    "report.analysis",
    "threat_intelligence.summary",
}


def _setting_json(namespace: str, key: str, default: object) -> object:
    raw = _setting_value(namespace, key)
    if not raw:
        return default
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return default


def _validated_ai_endpoint(value: object) -> str:
    endpoint = str(value or "").strip().rstrip("/")
    parsed = urlparse(endpoint)
    hostname = (parsed.hostname or "").lower()
    configured_hostname = (urlparse(str(current_app.config.get("OLLAMA_ENDPOINT") or "")).hostname or "").lower()
    allowed = {
        item.strip().lower()
        for item in str(current_app.config.get("AI_ALLOWED_PROVIDER_HOSTS") or "").split(",")
        if item.strip()
    }
    if configured_hostname:
        allowed.add(configured_hostname)
    if parsed.scheme not in {"http", "https"} or not hostname or parsed.username or parsed.password:
        raise ValueError("Endpoint must be an HTTP(S) URL without embedded credentials.")
    if hostname not in allowed:
        raise ValueError("Provider endpoint host is not in AI_ALLOWED_PROVIDER_HOSTS.")
    return endpoint


def _workload_assignment(workload: str) -> dict[str, str]:
    configured = _setting_json("ai.workloads", workload, {})
    document = configured if isinstance(configured, dict) else {}
    return {
        "provider": str(document.get("provider") or current_app.config.get("AI_PROVIDER", "ollama")),
        "model": str(document.get("model") or current_app.config.get("AI_MODEL", "qwen3:8b")),
    }


def _managed_prompt(workload: str) -> tuple[str | None, str | None]:
    version = str(_setting_json("ai.prompt.active", workload, "") or "")
    if not version:
        return None, None
    document = _setting_json("ai.prompt.versions", f"{workload}:{version}", {})
    if not isinstance(document, dict):
        return None, None
    content = str(document.get("content") or "").strip()
    return (content or None), version


def _configure_ai_failover(registry) -> dict[str, object]:
    document = _setting_json(
        "ai.platform",
        "failover",
        {"enabled": True, "order": ["ollama", "openai", "gemini", "perplexity"]},
    )
    policy = document if isinstance(document, dict) else {}
    enabled = bool(policy.get("enabled", True))
    order = policy.get("order", [])
    normalized = [str(item) for item in order] if isinstance(order, list) else []
    if registry is not None and hasattr(registry, "configure_failover"):
        registry.configure_failover(enabled=enabled, order=normalized)
        return registry.routing_policy
    return {"enabled": enabled, "order": normalized}


def _chat_route(message: str, uploads: list[dict[str, object]] | None = None) -> str:
    lower = message.lower()
    investigation_terms = {
        "current case",
        "evidence",
        "timeline",
        "report",
        "threat score",
        "analyze this",
        "summarize investigation",
        "forensic report",
        "case",
    }
    security_terms = {
        "sql injection",
        "xss",
        "malware",
        "phishing",
        "ransomware",
        "ioc",
        "mitre",
        "cve",
        "exploit",
        "hash",
        "powershell",
        "pcap",
        "incident response",
    }
    if uploads or any(term in lower for term in investigation_terms):
        return "investigation"
    if any(term in lower for term in security_terms):
        return "cybersecurity"
    return "general"


def _chat_system_prompt(route: str) -> str:
    base = (
        "You are CyberInvestigator's AI chat analyst and a senior cybersecurity investigator. "
        "Behave like a helpful ChatGPT-style assistant: answer greetings naturally, explain cybersecurity concepts clearly, "
        "and adapt depth to the user's question. Answer in Markdown. "
        "Use tables when comparing evidence, IOCs, MITRE ATT&CK techniques, timelines, or recommendations. "
        "Use fenced code blocks for commands, logs, JSON, regexes, and scripts. "
        "Never invent evidence, malware families, threat actors, or intelligence. Clearly distinguish recorded facts "
        "from hypotheses and recommend collection or verification when the supplied record is insufficient."
    )
    if route == "investigation":
        prompt = (
            base
            + " Use only the supplied case, evidence, timeline, reports, source catalog, conversation history, and "
            "uploads. Structure substantive answers with Assessment, Supporting evidence, Hypotheses, Confidence, "
            "and Recommended next steps. Prefix inferences with 'Hypothesis:'. Cite records with their supplied "
            "source IDs (for example [EVIDENCE:EV-001]); if no record supports a claim, say so explicitly."
        )
    elif route == "cybersecurity":
        prompt = (
            base + " Answer the cybersecurity question directly without assuming a specific case unless the user asks."
        )
    else:
        prompt = (
            base
            + " Treat this as normal conversation. Do not force an investigation summary or mention case context unless asked."
        )
    managed, version = _managed_prompt(f"chat.{route}")
    if managed:
        prompt += f"\nManaged workload instructions ({version}): {managed}"
    return prompt


def _chat_user_payload(
    user_message: str, context: dict[str, object], history: list[dict[str, object]], route: str
) -> str:
    clean_history = [
        {"role": str(item.get("role", ""))[:20], "content": str(item.get("content", ""))[:2000]}
        for item in history[-12:]
        if isinstance(item, dict)
    ]
    if route == "general":
        return json.dumps({"message": user_message, "history": clean_history}, default=str)
    if route == "cybersecurity":
        return json.dumps({"question": user_message, "history": clean_history}, default=str)
    scoped = _relevant_investigation_context(context, user_message)
    return json.dumps({"request": user_message, "history": clean_history, "context": scoped}, default=str)


def _relevant_investigation_context(context: dict[str, object], query: str) -> dict[str, object]:
    """Compress case context and retain the records most relevant to the request."""
    terms = {
        term for term in re.findall(r"[a-z0-9_.:-]{3,}", query.lower()) if term not in {"the", "and", "for", "with"}
    }
    full_requested = any(phrase in query.lower() for phrase in ("all evidence", "entire timeline", "full report"))

    def ranked(name: str, limit: int, fields: tuple[str, ...]) -> list[dict[str, object]]:
        records = [item for item in context.get(name, []) if isinstance(item, dict)]
        selected = records
        if not full_requested:
            scored = []
            for index, item in enumerate(records):
                searchable = " ".join(str(item.get(field) or "") for field in fields).lower()
                score = sum(searchable.count(term) for term in terms)
                scored.append((score, -index, item))
            scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
            selected = [item[2] for item in scored[:limit]]
        return [
            {
                field: (str(item.get(field))[:1200] if isinstance(item.get(field), str) else item.get(field))
                for field in fields
            }
            for item in selected
        ]

    case = context.get("case") if isinstance(context.get("case"), dict) else {}
    return {
        "case": {
            key: case.get(key)
            for key in ("id", "case_number", "title", "description", "severity", "priority", "status")
        },
        "evidence": ranked(
            "evidence", 8, ("evidence_number", "original_filename", "source_description", "analysis_summary", "sha256")
        ),
        "timeline": ranked("timeline", 12, ("event_type", "summary", "details")),
        "reports": ranked("reports", 5, ("title", "report_type", "status")),
        "source_catalog": _ai_grounding(context)["sources"],
        "uploaded_evidence": context.get("uploaded_evidence", []),
    }


def _ai_grounding(context: dict[str, object]) -> dict[str, object]:
    """Describe the real records available to the assistant without scoring truth."""
    case = context.get("case") if isinstance(context.get("case"), dict) else {}
    evidence = [item for item in context.get("evidence", []) if isinstance(item, dict)]
    timeline = [item for item in context.get("timeline", []) if isinstance(item, dict)]
    reports = [item for item in context.get("reports", []) if isinstance(item, dict)]
    sources: list[dict[str, object]] = []
    if case:
        case_number = str(case.get("case_number") or context.get("case_number") or "CASE")
        sources.append(
            {
                "id": f"CASE:{case_number}",
                "type": "case",
                "entity_id": case.get("id"),
                "label": case_number,
                "summary": case.get("title"),
            }
        )
    for item in evidence:
        number = str(item.get("evidence_number") or item.get("id") or "record")
        sources.append(
            {
                "id": f"EVIDENCE:{number}",
                "type": "evidence",
                "entity_id": item.get("id"),
                "label": number,
                "summary": item.get("original_filename"),
                "sha256": item.get("sha256"),
            }
        )
    for item in timeline:
        identifier = str(item.get("id") or "record")
        sources.append(
            {
                "id": f"TIMELINE:{identifier}",
                "type": "timeline",
                "entity_id": item.get("id"),
                "label": item.get("event_type") or "Timeline event",
                "summary": item.get("summary"),
                "occurred_at": item.get("occurred_at"),
            }
        )
    for item in reports:
        identifier = str(item.get("id") or "record")
        sources.append(
            {
                "id": f"REPORT:{identifier}",
                "type": "report",
                "entity_id": item.get("id"),
                "label": item.get("title") or item.get("report_type") or "Report",
                "summary": item.get("status"),
            }
        )
    categories = sum(bool(records) for records in (evidence, timeline, reports))
    if not case:
        level, rationale = "insufficient", "No accessible investigation is attached to this conversation."
    elif not sources[1:]:
        level, rationale = (
            "limited",
            "Only the investigation record is available; no supporting artifacts are recorded.",
        )
    elif categories >= 2 and evidence:
        level, rationale = (
            "moderate",
            "Multiple investigation record types are available; analyst validation is still required.",
        )
    else:
        level, rationale = "limited", "The response is grounded in a single supporting record category."
    next_steps: list[str] = []
    if case and not evidence:
        next_steps.append("Collect and preserve relevant evidence with hashes and acquisition details.")
    if evidence and not timeline:
        next_steps.append("Reconstruct a timeline from validated evidence and recorded activity.")
    if evidence and not reports:
        next_steps.append("Validate findings before creating an investigation report.")
    if not case:
        next_steps.append("Select an accessible investigation to enable evidence-grounded assistance.")
    return {
        "confidence": {
            "level": level,
            "basis": "available investigation data coverage",
            "rationale": rationale,
        },
        "counts": {"evidence": len(evidence), "timeline": len(timeline), "reports": len(reports)},
        "sources": sources,
        "recommended_next_steps": next_steps,
        "disclaimer": "Confidence describes source coverage, not the probability that a conclusion is correct.",
    }


def _instant_chat_reply(message: str) -> str | None:
    normalized = re.sub(r"[^a-z ]", "", message.lower()).strip()
    if normalized in {"hi", "hello", "hey", "good morning", "good afternoon", "good evening"}:
        return "Hello! How can I help with your investigation or cybersecurity question today?"
    if normalized in {"thanks", "thank you", "thankyou"}:
        return "You're welcome. Let me know what you'd like to investigate next."
    return None


def _chat_payload_from_request() -> tuple[dict[str, object], list[dict[str, object]] | None]:
    if request.files or request.form:
        history_raw = request.form.get("history", "[]")
        try:
            history = json.loads(history_raw)
        except json.JSONDecodeError:
            history = []
        document = {
            "message": request.form.get("message", ""),
            "case_id": request.form.get("case_id", ""),
            "conversation_id": request.form.get("conversation_id", ""),
            "history": history,
        }
        uploads = []
        for upload in request.files.getlist("files"):
            if not upload or not upload.filename:
                continue
            uploads.append(_register_chat_upload(upload, str(document.get("case_id") or "")))
        return document, uploads
    document = request.get_json(silent=True) or {}
    return document, None


def _register_chat_upload(upload, case_id: str) -> dict[str, object]:
    if not case_id:
        latest = _investigation_context(None).get("case_id")
        case_id = str(latest or "")
    if not case_id:
        raise ValueError("A case is required before uploading evidence into AI Chat.")
    parsed_case_id = _uuid(case_id, "case_id")
    if not _case_accessible(parsed_case_id):
        raise ValueError("You do not have access to that case.")
    created = _evidence_service().add_evidence(
        EvidenceAddRequest(
            case_id=parsed_case_id,
            evidence_number=f"CHAT-{int(time.time() * 1000)}",
            filename=upload.filename or "chat-upload.bin",
            content=upload.stream,
            media_type=upload.mimetype,
            source_description="Uploaded from AI Chat for contextual analysis.",
        )
    )
    _timeline_service().record_evidence_event(
        case_id=created.case_id,
        evidence_id=created.id,
        event_type="evidence.added",
        summary=f"Chat evidence {created.evidence_number} uploaded",
        details=created.original_filename,
    )
    _stamp_case_children(parsed_case_id)
    upload_record = Upload(
        owner_user_id=_current_user_id(),
        created_by_user_id=_current_user_id(),
        case_id=parsed_case_id,
        evidence_id=created.id,
        filename=created.original_filename,
        storage_path=created.storage_path,
    )
    _db().session.add(upload_record)
    _db().session.commit()
    analysis_response = _analyze_evidence_record(str(created.id))
    analysis = analysis_response.get_json() if hasattr(analysis_response, "get_json") else None
    return {"evidence": _evidence_json(created), "analysis": analysis}


def _generate_chat_reply(
    user_message: str,
    context: dict[str, object],
    history: list[dict[str, object]],
    uploads: list[dict[str, object]] | None = None,
) -> tuple[str | None, dict[str, object]]:
    registry, _, _ = _ai_runtime()
    route = _chat_route(user_message, uploads)
    assignment = _workload_assignment(f"chat.{route}")
    selected_provider = assignment["provider"]
    instant = _instant_chat_reply(user_message) if route == "general" else None
    if instant:
        return instant, {
            "provider": "local",
            "model": "instant",
            "available": True,
            "provider_called": False,
            "route": route,
            "response_id": None,
            "usage": None,
            "finish_reason": "completed",
        }
    status = _provider_status()
    selected_model = assignment["model"]
    ai_disabled = not bool(current_app.config.get("AI_ENABLED", True))
    test_live_ai_disabled = bool(current_app.config.get("TESTING")) and not bool(current_app.config.get("AI_ENABLED"))
    if registry is None or ai_disabled or test_live_ai_disabled:
        return (
            "No AI provider available. Ollama is not reachable, and no configured cloud provider can be used.",
            {
                **status,
                "provider_called": False,
                "route": route,
                "response_id": None,
                "usage": None,
                "finish_reason": "not_configured_or_disabled",
            },
        )
    try:
        started_at = time.perf_counter()
        provider = registry.select(selected_provider)
        resolved_provider = (
            provider.provider_name.value if hasattr(provider.provider_name, "value") else str(provider.provider_name)
        )
        actual_model = (
            selected_model
            if resolved_provider == selected_provider
            else str(getattr(provider, "model", None) or selected_model)
        )
        response = provider.generate(
            AIRequest(
                model=actual_model,
                messages=ai_messages(
                    _chat_system_prompt(route),
                    _chat_user_payload(user_message, context, history, route),
                ),
                temperature=float(current_app.config.get("AI_TEMPERATURE") or 0.2),
                max_output_tokens=int(current_app.config.get("AI_MAX_TOKENS") or 1200),
                metadata={"case_id": str(context.get("case_id") or "")},
            )
        )
        actual_provider = response.provider.value if hasattr(response.provider, "value") else str(response.provider)
        return (
            response.content,
            {
                **status,
                "provider": actual_provider,
                "model": response.model,
                "available": True,
                "provider_called": True,
                "route": route,
                "response_id": response.response_id,
                "usage": {
                    "input_tokens": response.usage.input_tokens if response.usage else None,
                    "output_tokens": response.usage.output_tokens if response.usage else None,
                },
                "finish_reason": "completed",
            },
        )
    except AIProviderUnavailable as error:
        if registry is not None and "provider" in locals():
            failed_name = (
                provider.provider_name.value
                if hasattr(provider.provider_name, "value")
                else str(provider.provider_name)
            )
            registry.mark_unavailable(failed_name)
        current_app.logger.warning("AI chat provider failed: %s", error)
        unavailable = "No AI provider available. Start Ollama locally or configure OpenAI, Gemini, or Perplexity."
        return unavailable, {
            **status,
            "available": False,
            "provider_called": True,
            "route": route,
            "response_id": None,
            "usage": None,
            "finish_reason": "error",
            "message": "Configured AI provider could not complete the request.",
        }
    except Exception as error:
        current_app.logger.warning("AI chat provider failed: %s", error)
        return (
            "I could not reach the configured AI provider for this request. "
            "Your case data and uploads were preserved. Check AI Provider settings or start Ollama locally.",
            {
                **status,
                "available": False,
                "provider_called": True,
                "route": route,
                "response_id": None,
                "usage": None,
                "finish_reason": "error",
                "message": "Configured AI provider could not complete the request.",
            },
        )


def _sse(payload: dict[str, object]) -> str:
    return f"data: {json.dumps(payload, default=str)}\n\n"


def _stream_provider_reply(
    message: str,
    context: dict[str, object],
    history: list[dict[str, object]],
    uploads: list[dict[str, object]] | None,
):
    registry, _, _ = _ai_runtime()
    route = _chat_route(message, uploads)
    assignment = _workload_assignment(f"chat.{route}")
    selected_provider = assignment["provider"]
    instant = _instant_chat_reply(message) if route == "general" else None
    if instant:
        return iter((instant,)), {
            "provider": "local",
            "model": "instant",
            "available": True,
            "provider_called": False,
            "route": route,
        }
    status = _provider_status()
    if registry is None or not bool(current_app.config.get("AI_ENABLED", True)):
        raise AIProviderUnavailable("No AI provider available.")
    provider = registry.select(selected_provider)
    provider_name = (
        provider.provider_name.value if hasattr(provider.provider_name, "value") else str(provider.provider_name)
    )
    model = (
        assignment["model"]
        if provider_name == selected_provider
        else str(getattr(provider, "model", None) or status.get("model") or "qwen3:8b")
    )
    request_payload = AIRequest(
        model=model,
        messages=ai_messages(_chat_system_prompt(route), _chat_user_payload(message, context, history, route)),
        temperature=float(current_app.config.get("AI_TEMPERATURE") or 0.2),
        max_output_tokens=int(current_app.config.get("AI_MAX_TOKENS") or 1200),
        stream=True,
        metadata={"case_id": str(context.get("case_id") or "")},
    )
    stream_status = {
        **status,
        "provider": provider_name,
        "model": model,
        "available": True,
        "provider_called": True,
        "route": route,
    }

    def resilient_stream():
        try:
            yield from provider.stream(request_payload)
        except AIProviderUnavailable:
            registry.mark_unavailable(provider_name)
            raise

    return resilient_stream(), stream_status


def _tail_file(path: Path, *, lines: int = 80) -> list[str]:
    """Read a bounded file tail without loading a potentially large log into memory."""
    if lines <= 0:
        return []
    try:
        with path.open("rb") as stream:
            stream.seek(0, 2)
            position = stream.tell()
            chunks: list[bytes] = []
            newline_count = 0
            while position > 0 and newline_count <= lines:
                block_size = min(8192, position)
                position -= block_size
                stream.seek(position)
                chunk = stream.read(block_size)
                chunks.append(chunk)
                newline_count += chunk.count(b"\n")
        return b"".join(reversed(chunks)).decode("utf-8", errors="replace").splitlines()[-lines:]
    except OSError:
        return []


def _audit_records(limit: int = 80) -> list[dict[str, object]]:
    records = []
    for line in _tail_file(Path(current_app.config["LOGS_FOLDER"]) / "audit.log", lines=limit):
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            records.append({"raw": line})
    return records


def _runtime_metrics() -> dict[str, object]:
    started_at = current_app.extensions.setdefault("cyberinvestigator_started_at", time.time())
    return {
        "uptime_seconds": round(time.time() - started_at, 2),
        "readiness": "operational",
    }


def _security_overview() -> dict[str, object]:
    session = _db().session
    failed_logins = (
        session.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.action == "auth.login", AuditLog.result == "failure")
        )
        or 0
    )
    successful_logins = (
        session.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.action == "auth.login", AuditLog.result == "success")
        )
        or 0
    )
    locked_accounts = session.scalar(select(func.count()).select_from(User).where(User.locked_until.is_not(None))) or 0
    active_sessions = (
        session.scalar(select(func.count()).select_from(UserSession).where(UserSession.active.is_(True))) or 0
    )
    open_alerts = list(
        session.scalars(
            select(SecurityAlert)
            .where(SecurityAlert.status == "open")
            .order_by(SecurityAlert.created_at.desc())
            .limit(10)
        )
    )
    recent_audit = list(session.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(20)))
    ai_failures = (
        session.scalar(
            select(func.count()).select_from(AuditLog).where(AuditLog.action.like("%ai%"), AuditLog.result == "failure")
        )
        or 0
    )
    plugin_failures = (
        session.scalar(
            select(func.count()).select_from(PluginExecution).where(PluginExecution.status.in_(["failed", "error"]))
        )
        or 0
    )
    threat_score = min(
        100, failed_logins * 8 + locked_accounts * 15 + len(open_alerts) * 10 + ai_failures * 5 + plugin_failures * 6
    )
    risk_level = (
        "critical"
        if threat_score >= 85
        else "high"
        if threat_score >= 65
        else "medium"
        if threat_score >= 35
        else "low"
    )
    recommendations = [
        "Review failed authentication sources and user agents.",
        "Confirm admin role changes and plugin changes are expected.",
        "Verify AI provider status before relying on live AI analysis.",
    ]
    if locked_accounts:
        recommendations.insert(0, "Review locked accounts before re-enabling access.")
    return {
        "threat_score": threat_score,
        "risk_level": risk_level,
        "confidence": 78 if recent_audit else 55,
        "priority": "urgent" if risk_level in {"critical", "high"} else "normal",
        "authentication": {
            "successful_logins": successful_logins,
            "failed_logins": failed_logins,
            "locked_accounts": locked_accounts,
            "online_users": active_sessions,
        },
        "system": {
            "database": health_ready()[0].get_json()["database"],
            "ai": _provider_status(),
            "plugins": plugin_inventory().get_json(),
            "metrics": monitoring_metrics().get_json(),
            "performance": _runtime_metrics(),
        },
        "ai_security_analyst": {
            "risk_level": risk_level,
            "threat_score": threat_score,
            "confidence_score": 78 if recent_audit else 55,
            "explanation": "Risk is derived from failed logins, account locks, open alerts, AI failures, and plugin failures.",
            "recommended_actions": recommendations,
        },
        "recent_alerts": [_security_alert_json(item) for item in open_alerts],
        "recent_audit_logs": [_audit_log_json(item) for item in recent_audit],
        "recommendations": recommendations,
    }


def _dicts_to_csv(rows: list[dict[str, object]]) -> str:
    if not rows:
        return ""
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=sorted({key for row in rows for key in row}))
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def _plugin_loader():
    return current_app.extensions.get("cyberinvestigator_plugin_loader")


def _ai_completion(task: str, payload: dict[str, object], *, max_tokens: int = 700) -> dict[str, object]:
    """Generate optional AI provider enrichment with a deterministic fallback envelope."""
    registry, _, _ = _ai_runtime()
    status = _provider_status()
    if not status.get("available") or registry is None:
        return {
            "available": False,
            "provider": status,
            "content": "No AI provider available. Local deterministic analysis is available and the workflow can continue.",
        }
    try:
        provider = registry.select(str(current_app.config.get("AI_PROVIDER", "ollama")))
        response = provider.generate(
            AIRequest(
                model=str(current_app.config.get("AI_MODEL") or status.get("model") or "qwen3:8b"),
                messages=ai_messages(
                    "You are CyberInvestigator's production cybersecurity analyst. Be concise, evidence-grounded, and do not invent facts.",
                    json.dumps({"task": task, "payload": payload}, default=str),
                ),
                temperature=0.2,
                max_output_tokens=max_tokens,
            )
        )
        return {"available": True, "provider": status, "content": response.content, "model": response.model}
    except Exception:
        current_app.logger.warning("AI enrichment failed for %s; details suppressed.", task)
        return {
            "available": False,
            "provider": {
                **status,
                "available": False,
                "message": "AI provider enrichment failed. Local fallback was used.",
            },
            "content": "AI enrichment is temporarily unavailable. Local deterministic analysis is available.",
        }


def _local_report_analysis(document: dict[str, object], context: dict[str, object]) -> str:
    evidence = context.get("evidence", []) if isinstance(context.get("evidence"), list) else []
    timeline = context.get("timeline", []) if isinstance(context.get("timeline"), list) else []
    findings = document.get("findings", []) if isinstance(document.get("findings"), list) else []
    indicators = document.get("iocs", []) if isinstance(document.get("iocs"), list) else []
    mappings = document.get("mitre_attack", []) if isinstance(document.get("mitre_attack"), list) else []
    recommendations = document.get("recommendations", []) if isinstance(document.get("recommendations"), list) else []
    source_complete = all(
        isinstance(item, dict) and isinstance(item.get("source"), dict) and item["source"].get("evidence_id")
        for item in findings
    )
    return (
        "## Recorded Content Review\n"
        f"The report contains {len(evidence)} evidence item(s), {len(timeline)} timeline event(s), "
        f"{len(findings)} source-linked finding(s), {len(indicators)} indicator(s), "
        f"{len(mappings)} recorded ATT&CK mapping(s), and {len(recommendations)} recorded recommendation(s).\n\n"
        "## Traceability\n"
        f"Finding source references are {'complete' if source_complete else 'incomplete and require investigator review'}.\n\n"
        "## Authorship\n"
        "This fallback review reports document structure only. It does not introduce findings, conclusions, "
        "recommendations, indicators, or ATT&CK mappings.\n\n"
        "## Review Status\n"
        f"The report remains **{document.get('review', {}).get('status', 'draft')}** until an authorized investigator "
        "reviews and approves it."
    )


def _investigation_context(case_id: str | None = None) -> dict[str, object]:
    session = _db().session
    parsed_case_id = None
    if case_id:
        try:
            parsed_case_id = _uuid(case_id, "case_id")
        except ValueError:
            parsed_case_id = None
    cache_key = f"context:{_current_user_role()}:{_current_user_id()}:{parsed_case_id or 'latest'}"
    cached = _runtime_cache().get(cache_key)
    if cached is not None:
        return cached
    context_scope = [
        Case.deleted_at.is_(None),
        Case.organization_id == _current_organization_id(),
    ]
    if not _is_admin():
        context_scope.append(Case.owner_user_id == _current_user_id())
    case = (
        session.get(Case, parsed_case_id)
        if parsed_case_id
        else session.scalar(select(Case).where(*context_scope).order_by(Case.opened_at.desc()).limit(1))
    )
    if case is None or not _case_accessible(case.id):
        empty = {
            "case_id": None,
            "case_number": None,
            "case": None,
            "evidence": [],
            "timeline": [],
            "reports": [],
            "plugins": [],
        }
        _runtime_cache().set(cache_key, empty, ttl_seconds=10)
        return empty
    evidence = [
        _evidence_json(item)
        for item in session.scalars(
            select(Evidence).where(Evidence.case_id == case.id, Evidence.deleted_at.is_(None)).limit(50)
        )
    ]
    timeline = [
        _timeline_json(item)
        for item in session.scalars(
            select(TimelineEvent)
            .where(TimelineEvent.case_id == case.id)
            .order_by(TimelineEvent.occurred_at.desc())
            .limit(50)
        )
    ]
    reports = [
        _report_json(item)
        for item in session.scalars(
            select(Report).where(Report.case_id == case.id).order_by(Report.generated_at.desc()).limit(20)
        )
    ]
    plugins = (
        plugin_inventory().get_json().get("plugins", [])
        if _is_admin() and current_app.extensions.get("cyberinvestigator_plugin_registry")
        else []
    )
    payload = {
        "case_id": str(case.id),
        "case_number": case.case_number,
        "case": _case_json(case),
        "evidence": evidence,
        "timeline": timeline,
        "reports": reports,
        "plugins": plugins,
    }
    _runtime_cache().set(cache_key, payload, ttl_seconds=10)
    return payload


def _build_report_document(case_id: UUID, report_type: str, ai_summary: dict[str, object]) -> dict[str, object]:
    context = _investigation_context(str(case_id))
    case = context["case"] or {}
    evidence = context["evidence"]
    timeline = context["timeline"]
    findings: list[dict[str, object]] = []
    iocs: list[dict[str, object]] = []
    mitre: list[dict[str, object]] = []
    for item in evidence:
        analysis = item.get("analysis_report") or {}
        if not isinstance(analysis, dict):
            continue
        source = {
            "evidence_id": item.get("id"),
            "evidence_number": item.get("evidence_number"),
            "sha256": item.get("sha256"),
        }
        for finding in analysis.get("findings", []) if isinstance(analysis.get("findings"), list) else []:
            if not isinstance(finding, dict):
                continue
            findings.append(
                {
                    "title": finding.get("title") or finding.get("type") or "Recorded forensic finding",
                    "detail": finding.get("detail") or finding.get("description"),
                    "severity": finding.get("severity"),
                    "confidence": finding.get("confidence"),
                    "source": source,
                    "authorship": "forensic_analysis",
                }
            )
        for indicator in analysis.get("ioc_table", []) if isinstance(analysis.get("ioc_table"), list) else []:
            if isinstance(indicator, dict) and indicator.get("value"):
                iocs.append({**indicator, "source": source})
        for mapping in analysis.get("mitre_mapping", []) if isinstance(analysis.get("mitre_mapping"), list) else []:
            if isinstance(mapping, dict) and mapping.get("technique_id"):
                mitre.append({**mapping, "source": source})
    recommendation_rows = list(
        _db().session.scalars(
            select(Recommendation).where(Recommendation.case_id == case_id).order_by(Recommendation.created_at)
        )
    )
    recommendations = [
        {
            "id": str(item.id),
            "priority": item.priority,
            "recommendation": item.recommendation,
            "rationale": item.rationale,
            "status": item.status,
            "authorship": "recorded_recommendation",
            "source_ai_reasoning_id": str(item.ai_reasoning_id),
        }
        for item in recommendation_rows
    ]
    reconstruction = _features().timeline.reconstruction.reconstruct(
        timeline,
        {
            str(item["id"]): item["analysis_report"]
            for item in evidence
            if isinstance(item.get("analysis_report"), dict)
        },
    )
    notes = [
        {"content": value, "authorship": "investigator", "source": f"case:{case_id}"}
        for value in (case.get("investigation_notes"), case.get("notes"))
        if value
    ]
    charts = {
        "timeline_by_group": {
            group: sum(1 for item in timeline if item["event_type"].split(".", 1)[0] == group)
            for group in sorted({item["event_type"].split(".", 1)[0] for item in timeline})
        },
        "evidence_by_type": {
            media_type: sum(1 for item in evidence if (item.get("media_type") or "unknown") == media_type)
            for media_type in sorted({item.get("media_type") or "unknown" for item in evidence})
        },
    }
    hunt_rows = list(
        _db().session.scalars(
            select(ThreatHunt).where(
                ThreatHunt.organization_id == _current_organization_id(),
                ThreatHunt.case_id == case_id,
            )
        )
    )
    hunt_ids = {item.id for item in hunt_rows}
    detection_rows = (
        list(
            _db().session.scalars(
                select(DetectionAlert).where(
                    DetectionAlert.organization_id == _current_organization_id(),
                    DetectionAlert.hunt_id.in_(hunt_ids),
                )
            )
        )
        if hunt_ids
        else []
    )
    evidence_ids = {UUID(str(item["id"])) for item in evidence}
    intelligence_relationships = (
        list(
            _db().session.scalars(
                select(IntelligenceRelationship).where(
                    IntelligenceRelationship.organization_id == _current_organization_id(),
                    IntelligenceRelationship.target_kind == "evidence",
                    IntelligenceRelationship.target_id.in_(evidence_ids),
                )
            )
        )
        if evidence_ids
        else []
    )
    related_indicator_ids = {item.source_id for item in intelligence_relationships if item.source_kind == "indicator"}
    related_indicators = (
        list(
            _db().session.scalars(
                select(IntelligenceIndicator).where(IntelligenceIndicator.id.in_(related_indicator_ids))
            )
        )
        if related_indicator_ids
        else []
    )
    return {
        "title": f"{context['case_number']} {report_type.title()} Report",
        "report_type": report_type,
        "generated_at": utc_now().isoformat(),
        "schema_version": "2.0",
        "executive_summary": (
            f"{context['case_number']} contains {len(evidence)} preserved evidence item(s), "
            f"{len(timeline)} recorded timeline event(s), and {len(findings)} source-linked forensic finding(s)."
        ),
        "technical_summary": {
            "evidence_count": len(evidence),
            "timeline_event_count": len(timeline),
            "finding_count": len(findings),
            "indicator_count": len(iocs),
            "attack_mapping_count": len(mitre),
        },
        "investigation_summary": context,
        "investigator_notes": notes,
        "evidence": evidence,
        "timeline": reconstruction,
        "findings": findings,
        "threat_assessment": {
            "status": "not_scored",
            "explanation": "No synthetic threat score is generated. Review source-linked findings and provider intelligence.",
        },
        "threat_score": None,
        "threat_intelligence": _threat_intelligence_projection(case_id, enrich=False),
        "intelligence_knowledge_graph": {
            "indicators": [_indicator_json(item) for item in related_indicators],
            "relationships": [
                {
                    "source_kind": item.source_kind,
                    "source_id": str(item.source_id),
                    "target_kind": item.target_kind,
                    "target_id": str(item.target_id),
                    "relationship_type": item.relationship_type,
                    "provenance": item.provenance,
                    "verified": item.verified,
                }
                for item in intelligence_relationships
            ],
        },
        "iocs": iocs[:50],
        "mitre_attack": mitre,
        "threat_hunting": {
            "hunts": [_hunt_json(item) for item in hunt_rows],
            "verified_detection_alerts": [
                {
                    "hunt_id": str(item.hunt_id),
                    "rule_id": str(item.rule_id),
                    "evidence_id": str(item.evidence_id),
                    "indicator_type": item.indicator_type,
                    "indicator_value": item.indicator_value,
                    "source": item.source,
                }
                for item in detection_rows
            ],
        },
        "ai_explanation": ai_summary,
        "recommendations": recommendations,
        "authorship": {
            "executive_summary": "system-generated from recorded counts",
            "findings": "forensic analysis",
            "investigator_notes": "investigator-authored",
            "ai_explanation": "AI-generated; requires investigator review",
        },
        "traceability": {
            "requirement": "Every finding includes an evidence ID, evidence number, and SHA-256 source reference.",
            "finding_sources_complete": all(item.get("source", {}).get("evidence_id") for item in findings),
        },
        "review": {
            "status": "draft",
            "approved_by": None,
            "approved_at": None,
            "digital_signature": None,
            "signature_status": "not_configured",
        },
        "appendix": {
            "chain_of_custody": "Evidence hashes, acquisition timestamps, and analysis reports are retained in the evidence records.",
            "plugins": context.get("plugins", []),
        },
        "charts": charts,
    }


def _report_markdown(document: dict[str, object]) -> str:
    lines = [f"# {document['title']}", "", f"Generated: {document['generated_at']}", ""]
    for title, key in (
        ("Executive Summary", "executive_summary"),
        ("Technical Summary", "technical_summary"),
        ("Investigation Summary", "investigation_summary"),
        ("Investigator Notes", "investigator_notes"),
        ("Evidence", "evidence"),
        ("Timeline", "timeline"),
        ("Source-linked Findings", "findings"),
        ("Threat Intelligence", "threat_intelligence"),
        ("Intelligence Knowledge Graph", "intelligence_knowledge_graph"),
        ("IOCs", "iocs"),
        ("MITRE ATT&CK", "mitre_attack"),
        ("Threat Hunting", "threat_hunting"),
        ("AI Explanation", "ai_explanation"),
        ("Recommendations", "recommendations"),
        ("Authorship", "authorship"),
        ("Traceability", "traceability"),
        ("Review", "review"),
        ("Appendix", "appendix"),
        ("Charts", "charts"),
    ):
        lines.extend([f"## {title}", ""])
        value = document.get(key)
        if isinstance(value, str | int):
            lines.append(str(value))
        else:
            lines.append("```json")
            lines.append(json.dumps(value, indent=2, default=str))
            lines.append("```")
        lines.append("")
    return "\n".join(lines)


def _report_html(document: dict[str, object]) -> str:
    sections = []
    for title, key in (
        ("Executive Summary", "executive_summary"),
        ("Technical Summary", "technical_summary"),
        ("Investigation Summary", "investigation_summary"),
        ("Investigator Notes", "investigator_notes"),
        ("Evidence", "evidence"),
        ("Timeline", "timeline"),
        ("Source-linked Findings", "findings"),
        ("Threat Intelligence", "threat_intelligence"),
        ("IOCs", "iocs"),
        ("MITRE ATT&CK", "mitre_attack"),
        ("AI Explanation", "ai_explanation"),
        ("Recommendations", "recommendations"),
        ("Authorship", "authorship"),
        ("Traceability", "traceability"),
        ("Review", "review"),
        ("Appendix", "appendix"),
        ("Charts", "charts"),
    ):
        value = document.get(key)
        body = (
            html.escape(str(value))
            if isinstance(value, str | int)
            else f"<pre>{html.escape(json.dumps(value, indent=2, default=str))}</pre>"
        )
        sections.append(f"<section><h2>{html.escape(title)}</h2>{body}</section>")
    return f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(str(document['title']))}</title><link rel='stylesheet' href='/static/css/report.css'></head><body><main><h1>{html.escape(str(document['title']))}</h1>{''.join(sections)}</main></body></html>"


def _report_csv(document: dict[str, object]) -> str:
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["section", "content"])
    for key, value in document.items():
        writer.writerow([key, json.dumps(value, default=str) if not isinstance(value, str) else value])
    return output.getvalue()


def _zip_docx(title: str, markdown: str) -> bytes:
    body = "".join(f"<w:p><w:r><w:t>{html.escape(line)}</w:t></w:r></w:p>" for line in markdown.splitlines())
    document_xml = f'<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{body}</w:body></w:document>'
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as docx:
        docx.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
        )
        docx.writestr(
            "_rels/.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
        )
        docx.writestr("word/document.xml", document_xml)
    return buffer.getvalue()


def _zip_xlsx(document: dict[str, object]) -> bytes:
    rows = [
        ["Section", "Content"],
        *[
            [key, json.dumps(value, default=str) if not isinstance(value, str) else value]
            for key, value in document.items()
        ],
    ]
    sheet_rows = "".join(
        "<row>" + "".join(f"<c t='inlineStr'><is><t>{html.escape(str(cell))}</t></is></c>" for cell in row) + "</row>"
        for row in rows
    )
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as xlsx:
        xlsx.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>',
        )
        xlsx.writestr(
            "_rels/.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
        )
        xlsx.writestr(
            "xl/workbook.xml",
            '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="Report" sheetId="1" r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></sheets></workbook>',
        )
        xlsx.writestr(
            "xl/_rels/workbook.xml.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>',
        )
        xlsx.writestr(
            "xl/worksheets/sheet1.xml",
            f'<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{sheet_rows}</sheetData></worksheet>',
        )
    return buffer.getvalue()


def _simple_pdf(text: str) -> bytes:
    safe = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    content = f"BT /F1 10 Tf 50 760 Td ({safe[:3500]}) Tj ET"
    objects = [
        "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
        "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
        "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj",
        "4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj",
        f"5 0 obj << /Length {len(content)} >> stream\n{content}\nendstream endobj",
    ]
    body = "%PDF-1.4\n" + "\n".join(objects) + "\ntrailer << /Root 1 0 R >>\n%%EOF"
    return body.encode("latin-1", errors="replace")


def _analyze_evidence_record(evidence_id: str):
    """Analyze one persisted evidence record and record the analysis event."""
    try:
        payload = _run_evidence_analysis(evidence_id)
    except ValueError as error:
        return _json_error(str(error), 400)
    except FileNotFoundError:
        return _json_error("Evidence custody file is unavailable.", 400)
    return jsonify(payload)


def _run_evidence_analysis(
    evidence_id: str,
    job_id: str | None = None,
    *,
    actor_id: UUID | None = None,
    actor_username: str | None = None,
    actor_role: str | None = None,
) -> dict[str, object]:
    """Run the full forensic evidence analysis and return a JSON-safe payload."""
    _update_analysis_job(job_id, 8, "Loading evidence record")
    try:
        evidence = _db().session.get(Evidence, _uuid(str(evidence_id), "evidence_id"))
    except ValueError as error:
        raise ValueError(str(error)) from error
    if evidence is None or evidence.deleted_at is not None:
        raise ValueError("Evidence was not found.")
    case = _db().session.get(Case, evidence.case_id)
    organization_id = case.organization_id if case and case.organization_id else _current_organization_id()
    analysis_run = EvidenceAnalysisRun(
        organization_id=organization_id,
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        requested_by_user_id=actor_id if actor_id is not None else _current_user_id(),
        analyzer=EvidenceLabAnalyzer.IDENTIFIER,
        analyzer_version=EvidenceLabAnalyzer.VERSION,
        status="running",
        evidence_sha256=evidence.sha256,
        module_manifest=json.dumps(list(EvidenceLabAnalyzer.MODULES)),
    )
    _db().session.add(analysis_run)
    _append_custody_event(
        evidence,
        "evidence.analysis.started",
        details=f"analyzer:{EvidenceLabAnalyzer.IDENTIFIER}; execution:non_executing_static",
        actor_id=actor_id,
    )
    _db().session.commit()
    _update_analysis_job(job_id, 16, "Reading custody file")
    path = _features().evidence.resolve_path(evidence.storage_path)
    try:
        result = EvidenceLabAnalyzer().analyze(
            path,
            evidence_number=evidence.evidence_number,
            original_filename=evidence.original_filename,
            sha256=evidence.sha256,
            progress=lambda value, step: _update_analysis_job(job_id, value, step),
        )
    except (OSError, ValueError) as error:
        analysis_run.status = "failed"
        analysis_run.error_code = error.__class__.__name__
        analysis_run.completed_at = utc_now()
        _append_custody_event(
            evidence,
            "evidence.analysis.failed",
            details=f"analysis_run:{analysis_run.id}; error_code:{error.__class__.__name__}",
            actor_id=actor_id,
        )
        _db().session.commit()
        if isinstance(error, OSError):
            raise FileNotFoundError(str(error)) from error
        raise
    _update_analysis_job(job_id, 72, "Saving forensic findings")
    analysis_run.status = "completed"
    analysis_run.integrity_verified = True
    analysis_run.completed_at = utc_now()
    for finding in result.findings:
        _db().session.add(
            ForensicFinding(
                organization_id=organization_id,
                case_id=evidence.case_id,
                evidence_id=evidence.id,
                analysis_run_id=analysis_run.id,
                finding_type=str(finding["finding_type"]),
                value=str(finding["value"]),
                source="static_analysis",
                verified_observation=True,
            )
        )
    for artifact in result.artifacts:
        _db().session.add(
            Artifact(
                evidence_id=evidence.id,
                analysis_run_id=analysis_run.id,
                artifact_type=str(artifact["artifact_type"])[:128],
                name=str(artifact["name"])[:512],
                source_location=str(artifact["source_location"])[:2048],
                content_hash=str(artifact["content_hash"]) if artifact.get("content_hash") else None,
            )
        )
    evidence.analysis_status = "completed"
    evidence.analysis_summary = result.summary
    evidence.analysis_report = json.dumps(result.report, default=str, indent=2)
    _db().session.commit()
    _timeline_service().record_evidence_event(
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        event_type="evidence.analysis.completed",
        summary=f"Forensic analysis completed for {evidence.evidence_number}",
        details=result.summary,
    )
    _invalidate_dashboard_cache()
    payload = {"summary": result.summary, "report": result.report}
    _update_analysis_job(job_id, 88, "Requesting optional evidence-grounded AI summary")
    payload["ai_explanation"] = _ai_completion(
        "Explain forensic evidence findings, encoding, compression, archive contents, hidden strings, flags, metadata, entropy, and next steps.",
        payload,
    )
    result.report["ai_explanation"] = payload["ai_explanation"]
    result.report["ai_explanation"]["provenance"] = "ai_generated_interpretation"
    evidence.analysis_report = json.dumps(result.report, default=str, indent=2)
    _db().session.commit()
    _append_custody_event(
        evidence,
        "evidence.analysis.completed",
        details=f"analysis_run:{analysis_run.id}; integrity_verified:true",
        actor_id=actor_id,
    )
    _record_evidence_audit(
        "evidence.analysis.completed",
        evidence,
        actor_id=actor_id,
        username=actor_username,
        role=actor_role,
        reason=f"SHA-256 verified · {evidence.sha256}",
    )
    _update_analysis_job(job_id, 100, "Completed")
    return payload


def _analysis_jobs() -> dict[str, dict[str, object]]:
    return current_app.extensions.setdefault("cyberinvestigator_jobs", {})


def _update_analysis_job(job_id: str | None, progress: int, step: str, **extra: object) -> None:
    if not job_id:
        return
    job = _analysis_jobs().setdefault(job_id, {})
    job.update({"progress": progress, "step": step, "updated_at": time.time(), **extra})


def _start_evidence_analysis_job(evidence_id: str) -> dict[str, object]:
    job_id = str(uuid4())
    app = current_app._get_current_object()
    actor_id = _current_user_id()
    actor_username = _current_username()
    actor_role = _current_user_role()
    evidence = _db().session.get(Evidence, _uuid(evidence_id, "evidence_id"))
    _analysis_jobs()[job_id] = {
        "id": job_id,
        "type": "evidence_analysis",
        "evidence_id": evidence_id,
        "case_id": str(evidence.case_id) if evidence is not None else None,
        "owner_user_id": str(evidence.owner_user_id) if evidence is not None and evidence.owner_user_id else None,
        "status": "queued",
        "progress": 0,
        "step": "Queued",
        "created_at": time.time(),
        "updated_at": time.time(),
    }

    def run() -> None:
        with app.app_context():
            try:
                _update_analysis_job(job_id, 3, "Uploading", status="running")
                payload = _run_evidence_analysis(
                    evidence_id,
                    job_id,
                    actor_id=actor_id,
                    actor_username=actor_username,
                    actor_role=actor_role,
                )
                _update_analysis_job(job_id, 100, "Completed", status="completed", result=payload)
            except Exception as error:
                current_app.logger.warning("Evidence analysis job failed: %s", error)
                failed_evidence = _db().session.get(Evidence, UUID(evidence_id))
                if failed_evidence is not None:
                    failed_evidence.analysis_status = "failed"
                    failed_run = _db().session.scalar(
                        select(EvidenceAnalysisRun)
                        .where(
                            EvidenceAnalysisRun.evidence_id == failed_evidence.id,
                            EvidenceAnalysisRun.status == "running",
                        )
                        .order_by(EvidenceAnalysisRun.created_at.desc())
                    )
                    if failed_run is not None:
                        failed_run.status = "failed"
                        failed_run.error_code = error.__class__.__name__
                        failed_run.completed_at = utc_now()
                        _append_custody_event(
                            failed_evidence,
                            "evidence.analysis.failed",
                            details=f"error_code:{error.__class__.__name__}",
                            actor_id=actor_id,
                        )
                    _db().session.commit()
                    _record_evidence_audit(
                        "evidence.analysis.failed",
                        failed_evidence,
                        actor_id=actor_id,
                        username=actor_username,
                        role=actor_role,
                        result="failure",
                        reason=error.__class__.__name__,
                    )
                safe_error = (
                    "Evidence integrity verification failed."
                    if isinstance(error, ValueError) and "integrity verification failed" in str(error)
                    else "Analysis could not complete safely. Review the server logs for this job."
                )
                _update_analysis_job(job_id, 100, "Failed", status="failed", error=safe_error)

    current_app.extensions["cyberinvestigator_job_dispatcher"].submit(run)
    return _analysis_jobs()[job_id]


def _start_report_enrichment_job(report_id: str, report_file: Path, context: dict[str, object]) -> dict[str, object]:
    """Enrich an already-created local report without blocking its request."""
    job_id = str(uuid4())
    app = current_app._get_current_object()
    _analysis_jobs()[job_id] = {
        "id": job_id,
        "type": "report_generation",
        "report_id": report_id,
        "status": "queued",
        "progress": 0,
        "step": "Queued",
        "created_at": time.time(),
        "updated_at": time.time(),
    }

    def run() -> None:
        with app.app_context():
            try:
                _update_analysis_job(job_id, 15, "Generating AI narrative", status="running")
                ai_summary = _ai_completion(
                    "Create an explainable report narrative using only the supplied investigation records. Separate "
                    "confirmed facts from hypotheses, cite evidence IDs for every finding, preserve investigator "
                    "authorship, and do not invent recommendations, indicators, actors, malware, or ATT&CK mappings.",
                    context,
                    max_tokens=1200,
                )
                document = json.loads(report_file.read_text(encoding="utf-8"))
                document["ai_explanation"] = ai_summary
                document["ai_summary"] = ai_summary
                document.setdefault("authorship", {})["ai_explanation"] = "AI-generated; requires investigator review"
                report_file.write_text(json.dumps(document, indent=2, default=str), encoding="utf-8")
                report = _db().session.get(Report, UUID(report_id))
                if report:
                    report.status = "completed"
                    _db().session.commit()
                _update_analysis_job(job_id, 100, "Completed", status="completed")
            except Exception as error:
                current_app.logger.warning("Report enrichment job failed: %s", error)
                report = _db().session.get(Report, UUID(report_id))
                if report:
                    report.status = "completed_local"
                    _db().session.commit()
                _update_analysis_job(job_id, 100, "Failed", status="failed", error=str(error))

    current_app.extensions["cyberinvestigator_job_dispatcher"].submit(run)
    return _analysis_jobs()[job_id]


@api_v1_blueprint.get("/ai/status")
def ai_status():  # type: ignore[no-untyped-def]
    """Return provider status without requiring external connectivity."""
    status = _provider_status()
    status["enabled"] = bool(current_app.config["AI_ENABLED"])
    status["fallback_available"] = True
    status["providers"] = _provider_status_payload()
    status["temperature"] = float(current_app.config.get("AI_TEMPERATURE") or 0.2)
    status["max_tokens"] = int(current_app.config.get("AI_MAX_TOKENS") or 1200)
    status["streaming"] = bool(current_app.config.get("AI_STREAMING", True))
    return jsonify(status)


@api_v1_blueprint.post("/ai/test-connection")
@require_role("admin")
def ai_test_connection():  # type: ignore[no-untyped-def]
    document = request.get_json(silent=True) or {}
    provider = str(document.get("provider") or current_app.config.get("AI_PROVIDER", "ollama")).strip().lower()
    registry, _, _ = _ai_runtime()
    if registry is None:
        return jsonify({"available": False, "provider": provider, "message": "AI runtime is unavailable."}), 503
    status = registry.test_connection(provider)
    _record_account_audit(
        "admin.ai_provider.connection_tested",
        f"ai_provider:{provider}",
        reason=f"available={status.available}; source={status.health_source}",
    )
    return jsonify(
        {
            "provider": status.provider,
            "available": status.available,
            "configured": status.configured,
            "model": status.model,
            "message": status.message,
            "endpoint": status.endpoint,
            "installed_models": list(status.installed_models),
            "health_source": status.health_source,
            "checked_at": status.checked_at,
        }
    )


@api_v1_blueprint.get("/admin/ai/management")
@require_role("admin")
def ai_management():  # type: ignore[no-untyped-def]
    """Return observed provider state, persisted routing, prompts, and provider-reported usage."""
    registry, _, _ = _ai_runtime()
    statuses = _provider_status_payload()
    failover = _configure_ai_failover(registry)
    credentials = {item.key for item in _db().session.scalars(select(Setting).where(Setting.namespace == "secret.ai"))}
    workload_assignments = {workload: _workload_assignment(workload) for workload in sorted(AI_WORKLOADS)}
    prompt_records = []
    for item in _db().session.scalars(
        select(Setting).where(Setting.namespace == "ai.prompt.versions").order_by(Setting.updated_at.desc())
    ):
        document = _setting_json(item.namespace, item.key, {})
        if not isinstance(document, dict):
            continue
        workload, _, version = item.key.partition(":")
        prompt_records.append(
            {
                "workload": workload,
                "version": version,
                "description": document.get("description"),
                "content": document.get("content"),
                "created_at": document.get("created_at") or _iso(item.updated_at),
                "created_by": document.get("created_by"),
                "active": str(_setting_json("ai.prompt.active", workload, "")) == version,
            }
        )
    reasoning = list(_db().session.scalars(select(AIReasoning).order_by(AIReasoning.created_at.desc()).limit(1000)))
    usage_by_model: dict[tuple[str, str], dict[str, object]] = {}
    for item in reasoning:
        key = (item.provider, item.model)
        record = usage_by_model.setdefault(
            key,
            {
                "provider": item.provider,
                "model": item.model,
                "requests_recorded": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "token_usage_status": "provider_reported",
            },
        )
        record["requests_recorded"] = int(record["requests_recorded"]) + 1
        if item.input_tokens is None and item.output_tokens is None:
            record["token_usage_status"] = "unavailable"
        record["input_tokens"] = int(record["input_tokens"]) + int(item.input_tokens or 0)
        record["output_tokens"] = int(record["output_tokens"]) + int(item.output_tokens or 0)
    providers = []
    for name, status in statuses.items():
        providers.append(
            {
                **status,
                "credential_configured": name in credentials
                or (name == "openai" and bool(current_app.config.get("AI_API_KEY"))),
                "credential_exposed": False,
            }
        )
    return jsonify(
        {
            "selected_provider": current_app.config.get("AI_PROVIDER"),
            "providers": providers,
            "workloads": workload_assignments,
            "prompt_versions": prompt_records,
            "failover": failover,
            "usage": list(usage_by_model.values()),
            "usage_notice": "Token counts are shown only when recorded from provider responses. Latency and cost are unavailable.",
        }
    )


@api_v1_blueprint.patch("/admin/ai/providers/<provider>")
@require_role("admin")
def update_ai_provider(provider: str):  # type: ignore[no-untyped-def]
    provider = provider.strip().lower()
    registry, _, _ = _ai_runtime()
    if registry is None or provider not in _provider_status_payload():
        return _json_error("Provider is not registered.", 404)
    document = request.get_json(silent=True) or {}
    allowed = {"model", "endpoint", "credential"}
    if any(key not in allowed for key in document):
        return _json_error("Only model, endpoint, and credential may be configured.", 400)
    metadata = _setting_json("ai.providers", provider, {})
    metadata = dict(metadata) if isinstance(metadata, dict) else {}
    if "model" in document:
        model = _normalize_text(document.get("model"), limit=255)
        if not model:
            return _json_error("Model must not be empty.", 400)
        metadata["model"] = model
    if "endpoint" in document:
        if provider != "ollama":
            return _json_error("A managed endpoint is supported only for the local Ollama adapter.", 400)
        try:
            metadata["endpoint"] = _validated_ai_endpoint(document.get("endpoint"))
        except ValueError as error:
            return _json_error(str(error), 400)
    if "credential" in document:
        credential = str(document.get("credential") or "")
        if provider == "ollama":
            return _json_error("The local Ollama adapter does not use an API credential.", 400)
        if not credential:
            return _json_error("Credential must not be empty.", 400)
        try:
            vault = CredentialVault(
                str(current_app.config.get("AI_CREDENTIAL_ENCRYPTION_KEY") or current_app.config["SECRET_KEY"])
            )
            _set_setting("secret.ai", provider, vault.encrypt(credential), "encrypted")
        except CredentialVaultUnavailable as error:
            return _json_error(str(error), 503)
    metadata["updated_at"] = utc_now().isoformat()
    metadata["updated_by"] = _current_username()
    _set_setting("ai.providers", provider, json.dumps(metadata), "json")
    managed_config = hydrate_ai_config(current_app.config, _db().session)
    current_app.extensions["cyberinvestigator_ai_registry"] = build_ai_registry(managed_config)
    _record_account_audit(
        "admin.ai_provider.updated",
        f"ai_provider:{provider}",
        reason=f"Updated fields: {', '.join(sorted(document))}; credential value was not logged.",
    )
    return ai_management()


@api_v1_blueprint.patch("/admin/ai/workloads/<workload>")
@require_role("admin")
def update_ai_workload(workload: str):  # type: ignore[no-untyped-def]
    if workload not in AI_WORKLOADS:
        return _json_error("Unknown AI workload.", 404)
    document = request.get_json(silent=True) or {}
    provider = str(document.get("provider") or "").strip().lower()
    model = _normalize_text(document.get("model"), limit=255)
    if provider not in _provider_status_payload():
        return _json_error("Provider is not registered.", 400)
    if not model:
        return _json_error("Model must not be empty.", 400)
    assignment = {"provider": provider, "model": model}
    _set_setting("ai.workloads", workload, json.dumps(assignment), "json")
    _record_account_audit(
        "admin.ai_workload.updated",
        f"ai_workload:{workload}",
        reason=f"provider={provider}; model={model}",
    )
    return jsonify({"workload": workload, **assignment})


@api_v1_blueprint.post("/admin/ai/prompts")
@require_role("admin")
def create_ai_prompt_version():  # type: ignore[no-untyped-def]
    document = request.get_json(silent=True) or {}
    workload = str(document.get("workload") or "")
    version = str(document.get("version") or "").strip()
    content = _normalize_text(document.get("content"), limit=20_000)
    if workload not in AI_WORKLOADS:
        return _json_error("Unknown AI workload.", 400)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", version):
        return _json_error("Prompt version must be a 1-64 character version identifier.", 400)
    if not content:
        return _json_error("Prompt content must not be empty.", 400)
    key = f"{workload}:{version}"
    if _setting_value("ai.prompt.versions", key):
        return _json_error("Prompt versions are immutable; choose a new version.", 409)
    prompt = {
        "content": content,
        "description": _normalize_text(document.get("description"), limit=2000),
        "created_at": utc_now().isoformat(),
        "created_by": _current_username(),
    }
    _set_setting("ai.prompt.versions", key, json.dumps(prompt), "json")
    if bool(document.get("activate", True)):
        _set_setting("ai.prompt.active", workload, json.dumps(version), "json")
    _record_account_audit(
        "admin.ai_prompt.created",
        f"ai_prompt:{key}",
        reason=f"activate={bool(document.get('activate', True))}",
    )
    return jsonify({"workload": workload, "version": version, "active": bool(document.get("activate", True))}), 201


@api_v1_blueprint.patch("/admin/ai/failover")
@require_role("admin")
def update_ai_failover():  # type: ignore[no-untyped-def]
    document = request.get_json(silent=True) or {}
    order = document.get("order", [])
    providers = set(_provider_status_payload())
    if not isinstance(order, list) or not order or any(str(item) not in providers for item in order):
        return _json_error("Failover order must contain registered providers.", 400)
    if len(set(map(str, order))) != len(order):
        return _json_error("Failover order must not contain duplicates.", 400)
    policy = {"enabled": bool(document.get("enabled", True)), "order": [str(item) for item in order]}
    _set_setting("ai.platform", "failover", json.dumps(policy), "json")
    registry, _, _ = _ai_runtime()
    _configure_ai_failover(registry)
    _record_account_audit(
        "admin.ai_failover.updated",
        "ai_platform:failover",
        reason=f"enabled={policy['enabled']}; order={','.join(policy['order'])}",
    )
    return jsonify(policy)


@api_v1_blueprint.get("/openapi.json")
def openapi_spec():  # type: ignore[no-untyped-def]
    return jsonify(build_openapi_spec(current_app, include_internal=_is_admin()))


@api_v1_blueprint.get("/developer/catalog")
@require_role("user")
def developer_catalog():  # type: ignore[no-untyped-def]
    """Describe implemented developer resources and clearly labeled previews."""
    project_root = Path(current_app.config["PROJECT_ROOT"])
    changelog = project_root / "CHANGELOG.md"
    try:
        release_notes = changelog.read_text(encoding="utf-8") if changelog.is_file() else None
    except OSError:
        release_notes = None
    spec = build_openapi_spec(current_app, include_internal=_is_admin())
    operation_count = sum(
        1 for path in spec["paths"].values() for method in path if method in {"get", "post", "put", "patch", "delete"}
    )
    return jsonify(
        {
            "api": {
                "version": spec["x-api-version"],
                "openapi": spec["openapi"],
                "path_count": len(spec["paths"]),
                "operation_count": operation_count,
                "visibility": "administrator" if _is_admin() else "authenticated_user",
            },
            "guides": [
                {"title": "API guide", "path": "docs/api.md", "audience": "developers"},
                {"title": "Developer guide", "path": "docs/developer-guide.md", "audience": "contributors"},
                {
                    "title": "Plugin architecture",
                    "path": "docs/plugin-connector-architecture.md",
                    "audience": "integrators",
                },
                {"title": "Security architecture", "path": "docs/security-architecture.md", "audience": "security"},
            ],
            "sdks": {
                "python": {"status": "preview", "path": "sdk/python"},
                "typescript": {"status": "preview", "path": "sdk/typescript"},
                "java": {"status": "preview", "path": "sdk/java"},
                "generation_source": "/api/v1/openapi.json",
            },
            "webhooks": {
                "status": "contract_preparation",
                "subscription_api": "unavailable",
                "delivery_worker": "unavailable",
            },
            "release_notes": {
                "status": "available" if release_notes is not None else "unavailable",
                "content": release_notes,
            },
        }
    )


@api_v1_blueprint.post("/ai/chat")
def ai_chat():  # type: ignore[no-untyped-def]
    """Return a case-aware assistant response with provider fallback."""
    try:
        document, uploads = _chat_payload_from_request()
    except (ValueError, CaseManagementError, EvidenceManagementError) as error:
        return _json_error(str(error), 400)
    if not isinstance(document, dict) or not isinstance(document.get("message"), str):
        return jsonify({"error": "A JSON message string is required."}), 400
    if not document["message"].strip():
        return jsonify({"error": "A chat message must not be empty."}), 400
    user_message = document["message"].strip()
    registry, assistant, _ = _ai_runtime()
    if assistant is None:
        response = "The local investigation assistant is unavailable, but the application remains operational."
        _save_conversation(user_message, response, document.get("case_id"), document.get("conversation_id"))
        return jsonify({"available": False, "reply": response, "message": response, "analysis": {}})

    history = document.get("history", [])
    if not isinstance(history, list):
        history = []
    requested_case_id = str(document.get("case_id") or "").strip()
    if requested_case_id:
        try:
            parsed_case_id = _uuid(requested_case_id, "case_id")
        except ValueError as error:
            return _json_error(str(error), 400)
        if not _case_accessible(parsed_case_id):
            return _forbidden("You do not have access to this investigation.")
    route = "investigation" if requested_case_id else _chat_route(user_message, uploads)
    context = (
        _investigation_context(requested_case_id or None)
        if route == "investigation"
        else {"case_id": None, "evidence": [], "timeline": [], "reports": [], "plugins": []}
    )
    if uploads:
        context["uploaded_evidence"] = uploads
        context["evidence"] = _investigation_context(str(context.get("case_id") or "") or None).get(
            "evidence", context.get("evidence", [])
        )
    provider_reply, status = _generate_chat_reply(user_message, context, history, uploads)

    payload = assistant.respond(
        message=user_message,
        case_context=context,
        provider_reply=provider_reply,
        provider_status=status,
    )
    conversation = _save_conversation(
        user_message, str(payload["reply"]), context.get("case_id"), document.get("conversation_id")
    )
    return jsonify(
        {
            "available": bool(status.get("available")),
            "reply": payload["reply"],
            "message": payload["reply"],
            "analysis": payload["analysis"],
            "memory": payload["memory"],
            "context": context,
            "uploads": uploads or [],
            "provider_status": status,
            "conversation_id": str(conversation.conversation_id),
            "grounding": _ai_grounding(context),
        }
    )


@api_v1_blueprint.get("/ai/conversations")
def list_ai_conversations():  # type: ignore[no-untyped-def]
    statement = (
        select(AIConversation)
        .where(AIConversation.organization_id == _current_organization_id())
        .order_by(AIConversation.created_at.desc())
    )
    if not _is_admin():
        statement = statement.where(AIConversation.owner_user_id == _current_user_id())
    owner = request.args.get("owner_user_id")
    if owner and _is_admin():
        try:
            statement = statement.where(AIConversation.owner_user_id == _uuid(owner, "owner_user_id"))
        except ValueError as error:
            return _json_error(str(error), 400)
    search = _query_text()
    turns = list(_db().session.scalars(statement.limit(500)))
    grouped: dict[UUID, dict[str, object]] = {}
    for item in turns:
        if search and search not in f"{item.title} {item.user_message} {item.assistant_message}".lower():
            continue
        thread = grouped.setdefault(
            item.conversation_id,
            {
                "id": str(item.conversation_id),
                "title": item.title,
                "owner_user_id": str(item.owner_user_id) if item.owner_user_id else None,
                "case_id": str(item.case_id) if item.case_id else None,
                "created_at": _iso(item.created_at),
                "updated_at": _iso(item.updated_at),
                "message_count": 0,
            },
        )
        thread["message_count"] = int(thread["message_count"]) + 2
        if str(item.updated_at) > str(thread["updated_at"]):
            thread["updated_at"] = _iso(item.updated_at)
    items = sorted(grouped.values(), key=lambda item: str(item["updated_at"]), reverse=True)
    return jsonify({"items": items})


def _conversation_scope(conversation_id: str):
    parsed = _uuid(conversation_id, "conversation_id")
    statement = select(AIConversation).where(
        AIConversation.conversation_id == parsed,
        AIConversation.organization_id == _current_organization_id(),
    )
    if not _is_admin():
        statement = statement.where(AIConversation.owner_user_id == _current_user_id())
    return parsed, statement


@api_v1_blueprint.get("/ai/conversations/<conversation_id>")
def get_ai_conversation(conversation_id: str):  # type: ignore[no-untyped-def]
    try:
        parsed, statement = _conversation_scope(conversation_id)
    except ValueError as error:
        return _json_error(str(error), 400)
    turns = list(_db().session.scalars(statement.order_by(AIConversation.created_at.asc())))
    if not turns:
        return _json_error("Conversation was not found.", 404)
    messages = []
    for turn in turns:
        messages.extend(
            ({"role": "user", "content": turn.user_message}, {"role": "assistant", "content": turn.assistant_message})
        )
    return jsonify(
        {
            "id": str(parsed),
            "title": turns[0].title,
            "case_id": str(turns[-1].case_id) if turns[-1].case_id else None,
            "messages": messages,
        }
    )


@api_v1_blueprint.patch("/ai/conversations/<conversation_id>")
def rename_ai_conversation(conversation_id: str):  # type: ignore[no-untyped-def]
    try:
        _, statement = _conversation_scope(conversation_id)
    except ValueError as error:
        return _json_error(str(error), 400)
    title = _normalize_text((request.get_json(silent=True) or {}).get("title"), limit=255)
    if not title:
        return _json_error("A conversation title is required.", 400)
    turns = list(_db().session.scalars(statement))
    if not turns:
        return _json_error("Conversation was not found.", 404)
    for turn in turns:
        turn.title = title
        turn.updated_at = utc_now()
    _db().session.commit()
    return jsonify({"id": conversation_id, "title": title})


@api_v1_blueprint.delete("/ai/conversations/<conversation_id>")
def delete_ai_conversation(conversation_id: str):  # type: ignore[no-untyped-def]
    try:
        _, statement = _conversation_scope(conversation_id)
    except ValueError as error:
        return _json_error(str(error), 400)
    turns = list(_db().session.scalars(statement))
    if not turns:
        return _json_error("Conversation was not found.", 404)
    for turn in turns:
        _db().session.delete(turn)
    _db().session.commit()
    return jsonify({"deleted": True})


@api_v1_blueprint.post("/ai/chat/stream")
def ai_chat_stream():  # type: ignore[no-untyped-def]
    """Stream a chat response as server-sent events with graceful fallback."""

    def generate():
        try:
            document, uploads = _chat_payload_from_request()
            message = str(document.get("message") or "").strip()
            if not message:
                yield _sse({"type": "error", "message": "A chat message must not be empty."})
                return
            history = document.get("history", [])
            history = history if isinstance(history, list) else []
            requested_case_id = str(document.get("case_id") or "").strip()
            if requested_case_id:
                try:
                    parsed_case_id = _uuid(requested_case_id, "case_id")
                except ValueError as error:
                    yield _sse({"type": "error", "message": str(error)})
                    return
                if not _case_accessible(parsed_case_id):
                    yield _sse({"type": "error", "message": "You do not have access to this investigation."})
                    return
            route = "investigation" if requested_case_id else _chat_route(message, uploads)
            context = (
                _investigation_context(requested_case_id or None)
                if route == "investigation"
                else {"case_id": None, "evidence": [], "timeline": [], "reports": [], "plugins": []}
            )
            if uploads:
                context["uploaded_evidence"] = uploads
                context["evidence"] = _investigation_context(str(context.get("case_id") or "") or None).get(
                    "evidence", context.get("evidence", [])
                )
            _, assistant, _ = _ai_runtime()
            reply = ""
            try:
                chunks, status = _stream_provider_reply(message, context, history, uploads)
                for chunk in chunks:
                    reply += chunk
                    yield _sse({"type": "token", "content": chunk})
                if assistant is not None:
                    assistant.respond(
                        message=message, case_context=context, provider_reply=reply, provider_status=status
                    )
            except AIProviderUnavailable:
                provider_reply, status = _generate_chat_reply(message, context, history, uploads)
                if assistant is None:
                    reply = provider_reply or "AI assistant is unavailable, but the application remains operational."
                else:
                    payload = assistant.respond(
                        message=message, case_context=context, provider_reply=provider_reply, provider_status=status
                    )
                    reply = payload["reply"]
                for index in range(0, len(reply), 80):
                    yield _sse({"type": "token", "content": reply[index : index + 80]})
            conversation = _save_conversation(message, reply, context.get("case_id"), document.get("conversation_id"))
            yield _sse(
                {
                    "type": "done",
                    "available": bool(status.get("available")),
                    "provider_status": status,
                    "uploads": uploads or [],
                    "conversation_id": str(conversation.conversation_id),
                    "grounding": _ai_grounding(context),
                }
            )
        except Exception as error:
            current_app.logger.warning("Streaming AI chat failed safely: %s", error)
            yield _sse(
                {
                    "type": "error",
                    "message": "AI Chat could not complete the request. Local data remains safe; try again or inspect provider settings.",
                }
            )

    return Response(
        stream_with_context(generate()), mimetype="text/event-stream", headers={"Cache-Control": "no-cache"}
    )


@api_v1_blueprint.post("/ai/analyze")
def ai_analyze():  # type: ignore[no-untyped-def]
    """Analyze supplied text or a stored evidence record with local fallback capabilities."""
    document = request.get_json(silent=True) or {}
    _, _, analyzer = _ai_runtime()
    if analyzer is None:
        return jsonify({"error": "Analysis engine unavailable."}), 503
    evidence_id = document.get("evidence_id")
    if evidence_id:
        return _analyze_evidence_record(str(evidence_id))
    text = str(document.get("text") or document.get("message") or "")
    if not text.strip():
        return _json_error("text or evidence_id is required.", 400)
    payload = analyzer.analyze_text(text).as_dict()
    payload["ai_explanation"] = _ai_completion(
        "Explain supplied cybersecurity text, IOCs, ATT&CK mapping, and threat score.", payload
    )
    return jsonify(payload)


@api_v1_blueprint.post("/ai/timeline-summary")
def ai_timeline_summary():  # type: ignore[no-untyped-def]
    document = request.get_json(silent=True) or {}
    context = _investigation_context(str(document.get("case_id") or "") or None)
    return jsonify(
        _ai_completion(
            "Summarize the investigation timeline and identify gaps, correlations, and next actions.", context
        )
    )


@api_v1_blueprint.post("/ai/explain-ioc")
def ai_explain_ioc():  # type: ignore[no-untyped-def]
    document = request.get_json(silent=True) or {}
    indicator = str(document.get("indicator") or "").strip()
    if not indicator:
        return _json_error("indicator is required.", 400)
    _, _, analyzer = _ai_runtime()
    local = analyzer.analyze_text(indicator).as_dict() if analyzer else {"iocs": {}}
    return jsonify(
        _ai_completion(
            "Explain this IOC, likely investigation relevance, and safe validation steps.",
            {"indicator": indicator, "local_analysis": local},
        )
    )


@api_v1_blueprint.post("/ai/explain-malware")
def ai_explain_malware():  # type: ignore[no-untyped-def]
    document = request.get_json(silent=True) or {}
    text = str(document.get("text") or "").strip()
    if not text:
        return _json_error("text is required.", 400)
    return jsonify(
        _ai_completion(
            "Explain suspected malware behavior, ATT&CK techniques, containment, and evidence needs.", {"text": text}
        )
    )


@api_v1_blueprint.post("/ai/analyze-log")
def ai_analyze_log():  # type: ignore[no-untyped-def]
    document = request.get_json(silent=True) or {}
    text = str(document.get("text") or "").strip()
    if not text:
        return _json_error("text is required.", 400)
    _, _, analyzer = _ai_runtime()
    local = analyzer.analyze_text(text).as_dict() if analyzer else {}
    return jsonify(
        {
            "analysis": local,
            "ai_explanation": _ai_completion(
                "Analyze these logs for suspicious activity, severity, and investigation actions.", local
            ),
        }
    )


@api_v1_blueprint.post("/ai/analyze-email-header")
def ai_analyze_email_header():  # type: ignore[no-untyped-def]
    document = request.get_json(silent=True) or {}
    text = str(document.get("text") or "").strip()
    if not text:
        return _json_error("text is required.", 400)
    _, _, analyzer = _ai_runtime()
    local = analyzer.analyze_text(text).as_dict() if analyzer else {}
    return jsonify(
        {
            "analysis": local,
            "ai_explanation": _ai_completion(
                "Analyze email headers for phishing, spoofing, relay anomalies, and validation status.", local
            ),
        }
    )


@api_v1_blueprint.get("/plugins")
def plugin_inventory():  # type: ignore[no-untyped-def]
    """Return a simple, structured view of registered plugins and their availability."""
    registry = current_app.extensions.get("cyberinvestigator_plugin_registry")
    loader = _plugin_loader()
    enabled = bool(current_app.config.get("PLUGINS_ENABLED", True))
    if registry is None:
        return jsonify({"enabled": enabled, "count": 0, "plugins": []})

    plugins = []
    if loader is not None:
        metadata_records = [(record.plugin.metadata, record.status.value) for record in loader._loaded.values()]
    else:
        try:
            metadata_records = [(metadata, "enabled") for metadata in registry.list_metadata()]
        except AttributeError:
            metadata_records = []

    for metadata, lifecycle_status in metadata_records:
        if not isinstance(metadata, PluginMetadata):
            continue
        granted = _setting_json("plugin.permissions", metadata.identifier, [])
        granted_permissions = [str(item) for item in granted] if isinstance(granted, list) else []
        plugins.append(
            {
                "id": metadata.identifier,
                "name": metadata.name,
                "version": metadata.version,
                "description": metadata.description,
                "supported_artifact_types": [
                    item.value if hasattr(item, "value") else str(item) for item in metadata.supported_artifact_types
                ],
                "capabilities": list(metadata.capabilities),
                "category": metadata.category,
                "requested_permissions": list(metadata.permissions),
                "granted_permissions": granted_permissions,
                "permissions_satisfied": set(metadata.permissions).issubset(granted_permissions),
                "configuration_schema": dict(metadata.configuration.schema),
                "configuration_defaults": dict(metadata.configuration.defaults),
                "configuration": _setting_json("plugin.configuration", metadata.identifier, {}),
                "configured": bool(_setting_value("plugin.configuration", metadata.identifier)),
                "credential_configured": bool(_setting_value("secret.plugin", metadata.identifier)),
                "credential_exposed": False,
                "connector_operations": [
                    operation
                    for operation, method_name in (("health", "health"), ("sync", "synchronize"))
                    if callable(
                        getattr(
                            loader._loaded[metadata.identifier].plugin
                            if loader is not None
                            else registry.get(metadata.identifier),
                            method_name,
                            None,
                        )
                    )
                ],
                "dependencies": [
                    {
                        "name": dep.name,
                        "version_specifier": dep.version_specifier,
                        "required": dep.required,
                    }
                    for dep in metadata.dependencies
                ],
                "status": lifecycle_status,
                "marketplace_ready": False,
                "marketplace_readiness": "not_evaluated",
                "validation": "valid",
                "versioning": {"current": metadata.version, "identifier": metadata.identifier},
            }
        )

    return jsonify({"enabled": enabled, "count": len(plugins), "plugins": plugins})


def _loaded_plugin(plugin_id: str):
    loader = _plugin_loader()
    if loader is None:
        raise PluginLoadError("Plugin loader is unavailable.")
    return loader._get_loaded(plugin_id)


def _plugin_runtime_inputs(plugin_id: str) -> tuple[dict[str, object], dict[str, str]]:
    configuration = _setting_json("plugin.configuration", plugin_id, {})
    config_document = dict(configuration) if isinstance(configuration, dict) else {}
    encrypted = _setting_value("secret.plugin", plugin_id)
    if not encrypted:
        return config_document, {}
    vault = CredentialVault(
        str(current_app.config.get("PLUGIN_CREDENTIAL_ENCRYPTION_KEY") or current_app.config["SECRET_KEY"])
    )
    decrypted = json.loads(vault.decrypt(encrypted))
    credentials = {str(key): str(value) for key, value in decrypted.items()} if isinstance(decrypted, dict) else {}
    return config_document, credentials


@api_v1_blueprint.get("/admin/plugins/management")
@require_role("admin")
def plugin_management():  # type: ignore[no-untyped-def]
    inventory = plugin_inventory().get_json()
    jobs = [item for item in _analysis_jobs().values() if str(item.get("type", "")).startswith("plugin_connector_")]
    health = {
        item.key: _setting_json(item.namespace, item.key, {})
        for item in _db().session.scalars(select(Setting).where(Setting.namespace == "plugin.health"))
    }
    synchronizations = {
        item.key: _setting_json(item.namespace, item.key, {})
        for item in _db().session.scalars(select(Setting).where(Setting.namespace == "plugin.sync"))
    }
    failed_jobs = [item for item in jobs if item.get("status") == "failed"]
    return jsonify(
        {
            **inventory,
            "health": health,
            "synchronizations": synchronizations,
            "jobs": jobs[-100:],
            "errors": failed_jobs[-50:],
            "updates": [],
            "updates_notice": "No marketplace or update source is configured; update availability is unknown.",
            "runtime": {
                "state": (
                    "disabled"
                    if not inventory["enabled"]
                    else "degraded"
                    if current_app.extensions.get("cyberinvestigator_plugin_load_error")
                    else "ready"
                ),
                "load_error": bool(current_app.extensions.get("cyberinvestigator_plugin_load_error")),
                "isolation": "trusted_process",
                "future_isolation": "external worker boundary prepared",
            },
            "categories": ["analysis", *[item.value for item in ConnectorCategory]],
            "allowed_permissions": sorted(PLUGIN_RUNTIME_PERMISSIONS),
        }
    )


@api_v1_blueprint.patch("/admin/plugins/<plugin_id>/configuration")
@require_role("admin")
def update_plugin_configuration(plugin_id: str):  # type: ignore[no-untyped-def]
    try:
        record = _loaded_plugin(plugin_id)
    except PluginLoadError as error:
        return _json_error(str(error), 404)
    document = request.get_json(silent=True) or {}
    configuration = document.get("configuration", {})
    credentials = document.get("credentials", {})
    grants = document.get("granted_permissions", [])
    if not isinstance(configuration, dict) or not isinstance(credentials, dict) or not isinstance(grants, list):
        return _json_error("Configuration, credentials, and granted_permissions must use their declared shapes.", 400)
    metadata = record.plugin.metadata
    schema = dict(metadata.configuration.schema)
    public_keys = {
        str(key)
        for key, definition in schema.items()
        if not (isinstance(definition, dict) and definition.get("secret") is True)
    }
    secret_keys = {
        str(key)
        for key, definition in schema.items()
        if isinstance(definition, dict) and definition.get("secret") is True
    }
    if set(configuration) - public_keys:
        return _json_error("Configuration contains keys not declared by the plugin schema.", 400)
    if set(credentials) - secret_keys:
        return _json_error("Credentials contain keys not declared as secret by the plugin schema.", 400)
    for key, value in configuration.items():
        definition = schema.get(key)
        if not isinstance(definition, dict):
            continue
        expected = definition.get("type")
        valid_type = (
            expected in {None, "string"}
            and isinstance(value, str)
            or expected == "boolean"
            and isinstance(value, bool)
            or expected == "integer"
            and isinstance(value, int)
            and not isinstance(value, bool)
            or expected == "number"
            and isinstance(value, int | float)
            and not isinstance(value, bool)
        )
        if not valid_type:
            return _json_error(f"Configuration field {key} does not match its declared type.", 400)
        choices = definition.get("enum")
        if isinstance(choices, list) and value not in choices:
            return _json_error(f"Configuration field {key} is not an allowed value.", 400)
    if any(not isinstance(value, str) or not value for value in credentials.values()):
        return _json_error("Credential values must be non-empty strings.", 400)
    requested = set(metadata.permissions)
    granted = {str(item) for item in grants}
    if not granted.issubset(requested) or not granted.issubset(PLUGIN_RUNTIME_PERMISSIONS):
        return _json_error("Granted permissions must be declared by the plugin and allowed by platform policy.", 400)
    _set_setting("plugin.configuration", plugin_id, json.dumps(configuration), "json")
    _set_setting("plugin.permissions", plugin_id, json.dumps(sorted(granted)), "json")
    if credentials:
        try:
            vault = CredentialVault(
                str(current_app.config.get("PLUGIN_CREDENTIAL_ENCRYPTION_KEY") or current_app.config["SECRET_KEY"])
            )
            _set_setting("secret.plugin", plugin_id, vault.encrypt(json.dumps(credentials)), "encrypted")
        except CredentialVaultUnavailable as error:
            return _json_error(str(error), 503)
    _record_account_audit(
        "admin.plugin.configuration.updated",
        f"plugin:{plugin_id}",
        reason=(
            f"configuration_keys={','.join(sorted(configuration)) or 'none'}; "
            f"credential_keys={','.join(sorted(credentials)) or 'unchanged'}; "
            f"permissions={','.join(sorted(granted)) or 'none'}"
        ),
    )
    return plugin_management()


@api_v1_blueprint.post("/admin/plugins/<plugin_id>/<operation>")
@require_role("admin")
def run_plugin_operation(plugin_id: str, operation: str):  # type: ignore[no-untyped-def]
    if operation not in {"health", "sync"}:
        return _json_error("Connector operation must be health or sync.", 404)
    try:
        loaded = _loaded_plugin(plugin_id)
        configuration, credentials = _plugin_runtime_inputs(plugin_id)
    except (PluginLoadError, CredentialVaultUnavailable, json.JSONDecodeError) as error:
        return _json_error(str(error), 400)
    if loaded.status.value != "enabled":
        return _json_error("Plugin must be enabled before connector operations can run.", 409)
    method_name = "health" if operation == "health" else "synchronize"
    method = getattr(loaded.plugin, method_name, None)
    if not callable(method):
        return _json_error(f"Plugin does not implement connector {operation}.", 409)
    job_id = str(uuid4())
    cursor_document = _setting_json("plugin.sync", plugin_id, {})
    cursor = cursor_document.get("cursor") if isinstance(cursor_document, dict) else None
    _analysis_jobs()[job_id] = {
        "id": job_id,
        "type": f"plugin_connector_{operation}",
        "plugin_id": plugin_id,
        "status": "queued",
        "progress": 0,
        "step": "Queued",
        "created_at": time.time(),
        "updated_at": time.time(),
    }
    app = current_app._get_current_object()
    actor_id = _current_user_id()
    actor_name = _current_username()
    actor_role = _current_user_role()

    def execute_connector_operation() -> None:
        with app.app_context():
            _update_analysis_job(job_id, 20, "Connecting", status="running")
            try:
                if operation == "health":
                    result = method(configuration=configuration, credentials=credentials)
                    if not isinstance(result, ConnectorHealth):
                        raise TypeError("Connector health must return ConnectorHealth.")
                    payload = {
                        "state": result.state.value,
                        "message": result.message,
                        "checked_at": result.checked_at,
                    }
                    namespace = "plugin.health"
                else:
                    result = method(configuration=configuration, credentials=credentials, cursor=cursor)
                    if not isinstance(result, ConnectorSyncResult):
                        raise TypeError("Connector synchronization must return ConnectorSyncResult.")
                    payload = {
                        "status": result.status,
                        "records_processed": result.records_processed,
                        "message": result.message,
                        "completed_at": result.completed_at,
                        "cursor": result.cursor,
                    }
                    namespace = "plugin.sync"
                _set_setting(namespace, plugin_id, json.dumps(payload), "json")
                _update_analysis_job(job_id, 100, "Completed", status="completed", result=payload)
                _db().session.add(
                    AuditLog(
                        user_id=actor_id,
                        username=actor_name,
                        role=actor_role,
                        action=f"admin.plugin.{operation}.completed",
                        result="success",
                        affected_object=f"plugin:{plugin_id}",
                        reason=f"job:{job_id}",
                    )
                )
                _db().session.commit()
            except Exception:
                current_app.logger.warning("Plugin connector operation failed for %s; details suppressed.", plugin_id)
                _update_analysis_job(
                    job_id,
                    100,
                    "Failed",
                    status="failed",
                    error="Connector operation failed; review protected server logs.",
                )
                _db().session.add(
                    AuditLog(
                        user_id=actor_id,
                        username=actor_name,
                        role=actor_role,
                        action=f"admin.plugin.{operation}.failed",
                        result="failure",
                        affected_object=f"plugin:{plugin_id}",
                        reason=f"job:{job_id}",
                    )
                )
                _db().session.commit()

    current_app.extensions["cyberinvestigator_job_dispatcher"].submit(execute_connector_operation)
    _record_account_audit(
        f"admin.plugin.{operation}.queued",
        f"plugin:{plugin_id}",
        reason=f"job:{job_id}",
    )
    return jsonify(_analysis_jobs()[job_id]), 202


@api_v1_blueprint.get("/admin/plugins/jobs/<job_id>")
@require_role("admin")
def plugin_operation_job(job_id: str):  # type: ignore[no-untyped-def]
    job = _analysis_jobs().get(job_id)
    if job is None or not str(job.get("type", "")).startswith("plugin_connector_"):
        return _json_error("Plugin operation job was not found.", 404)
    return jsonify(job)


@api_v1_blueprint.post("/plugins/reload")
def reload_plugins():  # type: ignore[no-untyped-def]
    registry = current_app.extensions.get("cyberinvestigator_plugin_registry")
    loader = current_app.extensions.get("cyberinvestigator_plugin_loader")
    if registry is None or loader is None:
        return jsonify({"enabled": False, "count": 0, "plugins": []})
    loaded = []
    for manifest in loader.discover():
        if manifest.identifier in loader._loaded:
            loaded.append(loader.reload(manifest.identifier))
        else:
            record = loader.load(manifest)
            if manifest.enabled:
                loader.enable(manifest.identifier)
            loaded.append(record)
    current_app.extensions["cyberinvestigator_plugin_loaded_count"] = len(loaded)
    _record_account_audit(
        "admin.plugin.discovery.completed",
        "plugin_registry",
        reason=f"loaded={len(loaded)}",
    )
    return plugin_inventory()


@api_v1_blueprint.post("/plugins/upload")
@require_role("admin")
def upload_plugin():  # type: ignore[no-untyped-def]
    loader = _plugin_loader()
    if loader is None:
        return _json_error("Plugin loader is unavailable.", 503)
    upload = request.files.get("plugin")
    if upload is None or not upload.filename:
        return _json_error("A plugin ZIP or plugin file is required.", 400)
    plugin_root = Path(current_app.config["PLUGINS_FOLDER"])
    plugin_root.mkdir(parents=True, exist_ok=True)
    safe_name = Path(upload.filename).name.replace(" ", "-")
    destination = (plugin_root / Path(safe_name).stem).resolve()
    if not str(destination).startswith(str(plugin_root.resolve())):
        return _json_error("Plugin destination is unsafe.", 400)
    if safe_name.lower().endswith(".zip"):
        try:
            with zipfile.ZipFile(BytesIO(upload.read())) as archive:
                members = archive.infolist()
                if len(members) > int(current_app.config.get("PLUGIN_ARCHIVE_MAX_FILES", 256)):
                    return _json_error("Plugin archive contains too many files.", 400)
                expanded_size = sum(member.file_size for member in members)
                if expanded_size > int(current_app.config.get("PLUGIN_ARCHIVE_MAX_EXPANDED_BYTES", 50 * 1024 * 1024)):
                    return _json_error("Plugin archive exceeds the expanded-size limit.", 400)
                for member in members:
                    target = (destination / member.filename).resolve()
                    if not target.is_relative_to(destination):
                        return _json_error("Plugin archive contains an unsafe path.", 400)
                    if member.flag_bits & 0x1:
                        return _json_error("Encrypted plugin archive members are not supported.", 400)
                    mode = member.external_attr >> 16
                    if stat.S_ISLNK(mode):
                        return _json_error("Plugin archive symbolic links are not allowed.", 400)
                manifests = [member for member in members if member.filename.replace("\\", "/") == "plugin.toml"]
                if len(manifests) != 1:
                    return _json_error("Plugin archive must contain exactly one plugin.toml manifest.", 400)
                try:
                    manifest_document = tomllib.loads(archive.read(manifests[0]).decode("utf-8"))
                    declared_hash = manifest_document["plugin"]["sha256"]
                except (KeyError, TypeError, UnicodeDecodeError, tomllib.TOMLDecodeError):
                    return _json_error("Uploaded plugin manifest must declare its module SHA-256.", 400)
                if not isinstance(declared_hash, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", declared_hash):
                    return _json_error("Uploaded plugin manifest SHA-256 must be a 64-character hex digest.", 400)
                destination.mkdir(parents=True, exist_ok=True)
                archive.extractall(destination)
        except zipfile.BadZipFile:
            return _json_error("Plugin archive is not a valid ZIP file.", 400)
    else:
        destination.mkdir(parents=True, exist_ok=True)
        upload.save(destination / safe_name)
    try:
        response = reload_plugins()
    except PluginLoadError as error:
        return _json_error(f"Plugin uploaded but validation failed: {error}", 400)
    inventory = response.get_json()
    _record_account_audit(
        "admin.plugin.installed",
        f"plugin_package:{safe_name}",
        reason=f"loaded={inventory.get('count', 0)}",
    )
    return jsonify({"uploaded": safe_name, "loaded": inventory.get("count", 0), "inventory": inventory}), 201


@api_v1_blueprint.post("/plugins/<plugin_id>/<action>")
@require_role("admin")
def plugin_lifecycle(plugin_id: str, action: str):  # type: ignore[no-untyped-def]
    loader = _plugin_loader()
    if loader is None:
        return _json_error("Plugin loader is unavailable.", 503)
    try:
        if action == "enable":
            loader.enable(plugin_id)
        elif action == "disable":
            loader.disable(plugin_id)
        elif action == "validate":
            record = loader._get_loaded(plugin_id)
            loader.validate_manifest(record.manifest)
            loader.validate_plugin(record.plugin, record.manifest)
        elif action == "update":
            loader.reload(plugin_id)
        elif action == "delete":
            record = loader._get_loaded(plugin_id)
            plugin_dir = record.manifest.module_file.parent.resolve()
            loader.unload(plugin_id)
            plugin_root = Path(current_app.config["PLUGINS_FOLDER"]).resolve()
            if plugin_dir.exists() and str(plugin_dir).startswith(str(plugin_root)):
                shutil.rmtree(plugin_dir)
            for namespace in (
                "plugin.configuration",
                "plugin.permissions",
                "plugin.health",
                "plugin.sync",
                "secret.plugin",
            ):
                setting = _db().session.scalar(
                    select(Setting).where(Setting.namespace == namespace, Setting.key == plugin_id)
                )
                if setting is not None:
                    _db().session.delete(setting)
            _db().session.commit()
        else:
            return _json_error("Unsupported plugin action.", 404)
    except (KeyError, PluginLoadError, OSError) as error:
        return _json_error(str(error), 400)
    _record_account_audit(
        f"admin.plugin.{action}",
        f"plugin:{plugin_id}",
    )
    return plugin_inventory()


@api_v1_blueprint.get("/cases")
def list_cases():  # type: ignore[no-untyped-def]
    include_related = request.args.get("include_related") == "true"
    statement = (
        select(Case)
        .where(
            Case.deleted_at.is_(None),
            Case.organization_id == _current_organization_id(),
        )
        .order_by(Case.opened_at.desc())
    )
    if not _is_admin():
        statement = statement.where(Case.owner_user_id == _current_user_id())
    records = list(_db().session.scalars(statement))
    cases = [_case_json(case, include_related=include_related) for case in records]
    case_ids = [case.id for case in records]
    counts: dict[str, dict[UUID, int]] = {"evidence_count": {}, "timeline_count": {}, "report_count": {}}
    if case_ids:
        for key, model in (("evidence_count", Evidence), ("timeline_count", TimelineEvent), ("report_count", Report)):
            rows = _db().session.execute(
                select(model.case_id, func.count()).where(model.case_id.in_(case_ids)).group_by(model.case_id)
            )
            counts[key] = {case_id: int(total) for case_id, total in rows}
    for item, record in zip(cases, records, strict=True):
        for key in counts:
            item[key] = counts[key].get(record.id, 0)
    query = _query_text()
    status = request.args.get("status", "all")
    priority = request.args.get("priority", "all")
    severity = request.args.get("severity", "all")
    owner = request.args.get("owner", "").strip().lower()
    tag = request.args.get("tag", "").strip().lower()
    if query:
        cases = [
            case
            for case in cases
            if query in case["case_number"].lower()
            or query in case["title"].lower()
            or query in (case["description"] or "").lower()
            or query in (case["owner"] or "").lower()
            or any(query in item.lower() for item in case["tags"])
            or any(query in item.lower() for item in case["notes"])
            or any(query in item.lower() for item in case["relationships"])
        ]
    if status != "all":
        cases = [case for case in cases if case["status"] == status]
    if priority != "all":
        cases = [case for case in cases if case["priority"] == priority]
    if severity != "all":
        cases = [case for case in cases if case["severity"] == severity]
    if owner:
        cases = [case for case in cases if owner in (case["owner"] or "").lower()]
    if tag:
        cases = [case for case in cases if any(tag == item.lower() for item in case["tags"])]
    sort = _sort_key("opened_at", {"case_number", "title", "severity", "priority", "owner", "opened_at", "status"})
    reverse = _direction() == "desc"
    cases.sort(key=lambda item: item.get(sort) or "", reverse=reverse)
    return jsonify(_page(cases, total=len(cases)))


@api_v1_blueprint.post("/cases")
def create_case():  # type: ignore[no-untyped-def]
    data = request.get_json(silent=True) or {}
    try:
        organization_settings = _organization_settings()
        quota = _organization_quota("investigations")
        if quota is not None:
            usage = (
                _db().session.scalar(
                    select(func.count())
                    .select_from(Case)
                    .where(
                        Case.organization_id == _current_organization_id(),
                        Case.deleted_at.is_(None),
                    )
                )
                or 0
            )
            if usage >= quota.limit_value:
                _organization_audit(
                    "organization.quota.blocked",
                    f"organization:{_current_organization_id()}:quota:investigations",
                    result="blocked",
                    reason=f"limit:{quota.limit_value} usage:{usage}",
                )
                return _json_error("Organization investigation quota has been reached.", 409)
        created = _case_service().create_case(
            CaseCreateRequest(
                case_number=str(data.get("case_number", "")),
                title=str(data.get("title", "")),
                description=data.get("description"),
                severity=str(data.get("severity") or organization_settings.get("default_case_severity") or "medium"),
            )
        )
        if not _is_admin() and not data.get("owner"):
            data["owner"] = _current_username()
        case_record = _apply_case_workspace_fields(created.id, data)
        _timeline_service().record_investigation_event(
            case_id=created.id,
            event_type="case.created",
            summary=f"Case {created.case_number} created",
            details=created.title,
        )
        _stamp_case_children(created.id)
        _record_case_audit("case.created", case_record)
        _invalidate_dashboard_cache()
        return jsonify(_case_json(case_record)), 201
    except (ValueError, CaseManagementError) as error:
        return _json_error(str(error), 400)


@api_v1_blueprint.get("/cases/<case_id>/workspace")
def case_workspace(case_id: str):  # type: ignore[no-untyped-def]
    """Return an ownership-scoped, read-only investigation workspace projection."""

    try:
        parsed_case_id = _uuid(case_id, "case_id")
    except ValueError as error:
        return _json_error(str(error), 400)
    if not _case_accessible(parsed_case_id):
        return _forbidden()

    session = _db().session
    case = session.get(Case, parsed_case_id)
    if case is None or case.deleted_at is not None:
        return _json_error("Case not found.", 404)

    evidence = list(
        session.scalars(
            select(Evidence)
            .where(Evidence.case_id == parsed_case_id, Evidence.deleted_at.is_(None))
            .order_by(Evidence.acquired_at.desc())
            .limit(12)
        )
    )
    timeline = list(
        session.scalars(
            select(TimelineEvent)
            .where(TimelineEvent.case_id == parsed_case_id)
            .order_by(TimelineEvent.occurred_at.desc())
            .limit(20)
        )
    )
    reports = list(
        session.scalars(
            select(Report).where(Report.case_id == parsed_case_id).order_by(Report.generated_at.desc()).limit(12)
        )
    )
    ai_records = list(
        session.scalars(
            select(AIReasoning)
            .where(AIReasoning.case_id == parsed_case_id)
            .order_by(AIReasoning.created_at.desc())
            .limit(6)
        )
    )
    recommendations = list(
        session.scalars(
            select(Recommendation)
            .where(Recommendation.case_id == parsed_case_id)
            .order_by(Recommendation.created_at.desc())
            .limit(6)
        )
    )
    timeline_payload = [_timeline_json(item) for item in timeline]
    threat_signals = [
        item
        for item in timeline_payload
        if str(item.get("threat_level") or "").lower() in {"critical", "high"}
        or any(term in str(item.get("event_type") or "").lower() for term in ("threat", "indicator", "ioc"))
    ]
    evidence_total = (
        session.scalar(
            select(func.count())
            .select_from(Evidence)
            .where(Evidence.case_id == parsed_case_id, Evidence.deleted_at.is_(None))
        )
        or 0
    )
    timeline_total = (
        session.scalar(select(func.count()).select_from(TimelineEvent).where(TimelineEvent.case_id == parsed_case_id))
        or 0
    )
    reports_total = (
        session.scalar(select(func.count()).select_from(Report).where(Report.case_id == parsed_case_id)) or 0
    )
    ai_total = (
        session.scalar(select(func.count()).select_from(AIReasoning).where(AIReasoning.case_id == parsed_case_id)) or 0
    ) + (
        session.scalar(select(func.count()).select_from(Recommendation).where(Recommendation.case_id == parsed_case_id))
        or 0
    )
    return jsonify(
        {
            "case": _case_json(case, include_related=False),
            "evidence": [_evidence_json(item) for item in evidence],
            "timeline": timeline_payload,
            "reports": [_report_json(item) for item in reports],
            "ai_findings": [
                {
                    "title": f"{record.provider} / {record.model}",
                    "body": _short_text(record.reasoning, "AI reasoning record available."),
                    "created_at": _iso(record.created_at),
                    "kind": "reasoning",
                }
                for record in ai_records
            ]
            + [
                {
                    "title": f"{item.priority.title()} priority recommendation",
                    "body": _short_text(item.recommendation, "Open recommendation."),
                    "created_at": _iso(item.created_at),
                    "kind": "recommendation",
                    "status": item.status,
                }
                for item in recommendations
            ],
            "threat_signals": threat_signals,
            "counts": {
                "evidence": evidence_total,
                "timeline": timeline_total,
                "reports": reports_total,
                "ai_findings": ai_total,
                "threat_signals": len(threat_signals),
            },
        }
    )


@api_v1_blueprint.patch("/cases/<case_id>")
def update_case(case_id: str):  # type: ignore[no-untyped-def]
    data = request.get_json(silent=True) or {}
    try:
        parsed_case_id = _uuid(case_id, "case_id")
        if not _case_accessible(parsed_case_id):
            return _forbidden()
        if any(field in data for field in ("title", "description", "severity")):
            updated = _case_service().update_case(
                parsed_case_id,
                CaseUpdateRequest(
                    title=data["title"] if "title" in data else CaseUpdateRequest.__dataclass_fields__["title"].default,
                    description=data["description"]
                    if "description" in data
                    else CaseUpdateRequest.__dataclass_fields__["description"].default,
                    severity=data["severity"]
                    if "severity" in data
                    else CaseUpdateRequest.__dataclass_fields__["severity"].default,
                ),
            )
            parsed_case_id = updated.id
        case_record = _apply_case_workspace_fields(parsed_case_id, data)
        _timeline_service().record_investigation_event(
            case_id=parsed_case_id,
            event_type="case.updated",
            summary=f"Case {case_record.case_number} updated",
            details="Case details, owner, priority, tags, notes, or relationships were updated.",
        )
        _stamp_case_children(parsed_case_id)
        _record_case_audit("case.updated", case_record)
        _invalidate_dashboard_cache()
        return jsonify(_case_json(case_record))
    except (ValueError, CaseManagementError) as error:
        return _json_error(str(error), 400)


@api_v1_blueprint.post("/cases/<case_id>/<action>")
def case_action(case_id: str, action: str):  # type: ignore[no-untyped-def]
    try:
        service = _case_service()
        parsed = _uuid(case_id, "case_id")
        if not _case_accessible(parsed):
            return _forbidden()
        if action == "delete" and not _is_admin():
            return _forbidden("Only administrators can delete investigations.")
        if action == "close":
            service.close_case(parsed)
            record = _db().session.get(Case, parsed)
            if record:
                record.status = "closed"
        elif action == "archive":
            service.archive_case(parsed)
            record = _db().session.get(Case, parsed)
            if record:
                record.status = "archived"
        elif action == "delete":
            service.delete_case(parsed)
            record = _db().session.get(Case, parsed)
            if record:
                record.status = "deleted"
        else:
            return _json_error("Unsupported case action.", 404)
        _timeline_service().record_investigation_event(
            case_id=parsed,
            event_type=f"case.{action}d" if action != "close" else "case.closed",
            summary=f"Case lifecycle changed: {action}",
            details=f"Investigation was {action}d by {_current_username()}.",
        )
        if record is not None:
            audit_action = "case.closed" if action == "close" else f"case.{action}d"
            _record_case_audit(audit_action, record)
        _invalidate_dashboard_cache()
        _db().session.commit()
        return jsonify(_case_json(_db().session.get(Case, parsed)))
    except (ValueError, CaseManagementError) as error:
        return _json_error(str(error), 400)


def _case_indicator_inventory(case_id: UUID) -> tuple[list[object], dict[tuple[str, str], list[dict[str, str]]]]:
    """Collect normalized indicators and their evidence provenance."""
    aliases = {"ip": "ipv4", "ip_address": "ipv4", "hash": "sha256"}
    normalized: dict[tuple[str, str], object] = {}
    sources: dict[tuple[str, str], list[dict[str, str]]] = {}
    records = _db().session.scalars(select(Evidence).where(Evidence.case_id == case_id, Evidence.deleted_at.is_(None)))
    for evidence in records:
        candidates: list[tuple[str, str]] = [("sha256", evidence.sha256)]
        report = _stored_json(evidence.analysis_report)
        if isinstance(report, dict):
            for item in report.get("ioc_table", []) if isinstance(report.get("ioc_table"), list) else []:
                if isinstance(item, dict) and item.get("type") and item.get("value"):
                    candidates.append((str(item["type"]), str(item["value"])))
        for raw_type, raw_value in candidates:
            indicator_type = aliases.get(raw_type.strip().lower(), raw_type.strip().lower())
            try:
                indicator = normalize_indicator(indicator_type, raw_value)
            except (KeyError, ValueError):
                continue
            key = (indicator.type.value, indicator.value)
            normalized[key] = indicator
            source = {
                "evidence_id": str(evidence.id),
                "evidence_number": evidence.evidence_number,
                "filename": evidence.original_filename,
            }
            if source not in sources.setdefault(key, []):
                sources[key].append(source)
    return list(normalized.values()), sources


def _threat_intelligence_projection(case_id: UUID, *, enrich: bool) -> dict[str, object]:
    indicators, sources = _case_indicator_inventory(case_id)
    engine = _features().threat_intelligence.engine
    result = engine.correlate(indicators) if enrich else engine.correlate([])
    if not enrich:
        result["indicators"] = [
            {
                "type": indicator.type.value,
                "value": indicator.value,
                "original_value": indicator.original_value,
                "status": "unknown",
                "findings": [],
            }
            for indicator in indicators
        ]
        result["summary"] = {
            "total": len(indicators),
            "enriched": 0,
            "unknown": len(indicators),
            "providers_queried": 0,
        }
    for item in result["indicators"]:
        item["sources"] = sources.get((str(item["type"]), str(item["value"])), [])
    findings = result.get("findings", [])
    result["reputation_counts"] = {
        reputation: sum(1 for item in findings if item.get("reputation") == reputation)
        for reputation in ("malicious", "suspicious", "benign")
    }
    result["attack_mappings"] = [
        {
            "technique_id": technique,
            "provider": finding["provider"],
            "indicator": finding["indicator"]["value"],
            "reference": finding.get("reference"),
        }
        for finding in findings
        for technique in finding.get("attack_techniques", [])
    ]
    result["case_id"] = str(case_id)
    return result


@api_v1_blueprint.get("/threat-intelligence")
def threat_intelligence_snapshot():  # type: ignore[no-untyped-def]
    case_id = request.args.get("case_id", "")
    try:
        parsed = _uuid(case_id, "case_id")
    except ValueError as error:
        return _json_error(str(error), 400)
    if not _case_accessible(parsed):
        return _forbidden()
    return jsonify(_threat_intelligence_projection(parsed, enrich=False))


@api_v1_blueprint.post("/threat-intelligence/enrich")
def enrich_threat_intelligence():  # type: ignore[no-untyped-def]
    document = request.get_json(silent=True) or {}
    try:
        parsed = _uuid(str(document.get("case_id") or ""), "case_id")
    except ValueError as error:
        return _json_error(str(error), 400)
    if not _case_accessible(parsed):
        return _forbidden()
    case = _db().session.get(Case, parsed)
    if case is None or case.deleted_at is not None:
        return _json_error("Case not found.", 404)
    result = _threat_intelligence_projection(parsed, enrich=True)
    _persist_intelligence_projection(parsed, result)
    if result.get("findings"):
        _timeline_service().record_investigation_event(
            case_id=parsed,
            event_type="threat_intelligence.enriched",
            summary=f"Threat intelligence enrichment returned {len(result['findings'])} provider finding(s)",
            details=f"Configured providers queried: {len(result.get('providers', []))}.",
        )
    providers = result.get("providers", [])
    _record_intelligence_audit(
        case,
        result="success",
        reason=(
            f"Enrichment completed with {len(providers)} configured provider(s); "
            f"{result['summary']['enriched']} indicator(s) returned findings."
        ),
    )
    return jsonify(result)


def _intelligence_audit(
    action: str,
    affected_object: str,
    reason: str,
    *,
    result: str = "success",
) -> None:
    _db().session.add(
        AuditLog(
            organization_id=_current_organization_id(),
            user_id=_current_user_id(),
            username=_current_username(),
            role=_current_user_role(),
            action=action,
            result=result,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            affected_object=affected_object,
            reason=reason,
        )
    )


def _safe_intelligence_attributes(value: object) -> dict[str, object]:
    def clean(item: object) -> object:
        if isinstance(item, dict):
            return {
                str(key)[:128]: clean(child)
                for key, child in item.items()
                if not any(
                    secret in str(key).lower() for secret in ("password", "secret", "token", "api_key", "credential")
                )
            }
        if isinstance(item, list):
            return [clean(child) for child in item[:200]]
        return item if isinstance(item, (str, int, float, bool, type(None))) else str(item)

    return clean(value) if isinstance(value, dict) else {}  # type: ignore[return-value]


def _upsert_intelligence_indicator(
    indicator_type: str,
    value: str,
    *,
    source: str,
    provider: str | None = None,
    reputation: str = "unknown",
    confidence: float | None = None,
    reference: str | None = None,
) -> IntelligenceIndicator:
    indicator = normalize_indicator(indicator_type, value)
    record = _db().session.scalar(
        select(IntelligenceIndicator).where(
            IntelligenceIndicator.organization_id == _current_organization_id(),
            IntelligenceIndicator.indicator_type == indicator.type.value,
            IntelligenceIndicator.normalized_value == indicator.value,
        )
    )
    if record is None:
        record = IntelligenceIndicator(
            organization_id=_current_organization_id(),
            indicator_type=indicator.type.value,
            normalized_value=indicator.value,
            source=source,
            provider=provider,
            reputation=reputation,
            confidence=confidence,
            reference=reference,
            created_by_user_id=_current_user_id(),
        )
        _db().session.add(record)
        _db().session.flush()
    else:
        record.last_seen_at = utc_now()
        record.updated_at = utc_now()
        if provider:
            record.provider = provider
            record.reputation = reputation
            record.confidence = confidence
            record.reference = reference
    return record


def _add_intelligence_relationship(
    *,
    source_kind: str,
    source_id: UUID,
    target_kind: str,
    target_id: UUID,
    relationship_type: str,
    provenance: str,
    reference: str | None = None,
    verified: bool = False,
    confidence: float | None = None,
) -> IntelligenceRelationship:
    relationship = _db().session.scalar(
        select(IntelligenceRelationship).where(
            IntelligenceRelationship.organization_id == _current_organization_id(),
            IntelligenceRelationship.source_kind == source_kind,
            IntelligenceRelationship.source_id == source_id,
            IntelligenceRelationship.target_kind == target_kind,
            IntelligenceRelationship.target_id == target_id,
            IntelligenceRelationship.relationship_type == relationship_type,
            IntelligenceRelationship.provenance == provenance,
        )
    )
    if relationship is None:
        relationship = IntelligenceRelationship(
            organization_id=_current_organization_id(),
            source_kind=source_kind,
            source_id=source_id,
            target_kind=target_kind,
            target_id=target_id,
            relationship_type=relationship_type,
            provenance=provenance,
            reference=reference,
            verified=verified,
            confidence=confidence,
            created_by_user_id=_current_user_id(),
        )
        _db().session.add(relationship)
    return relationship


def _persist_intelligence_projection(case_id: UUID, projection: dict[str, object]) -> None:
    for item in projection.get("indicators", []):
        if not isinstance(item, dict):
            continue
        indicator = _upsert_intelligence_indicator(
            str(item.get("type")),
            str(item.get("value")),
            source="evidence",
        )
        for source in item.get("sources", []):
            if not isinstance(source, dict) or not source.get("evidence_id"):
                continue
            _add_intelligence_relationship(
                source_kind="indicator",
                source_id=indicator.id,
                target_kind="evidence",
                target_id=UUID(str(source["evidence_id"])),
                relationship_type="observed_in",
                provenance=f"case:{case_id}",
                verified=True,
            )
    for finding in projection.get("findings", []):
        if not isinstance(finding, dict) or not isinstance(finding.get("indicator"), dict):
            continue
        indicator_data = finding["indicator"]
        indicator = _upsert_intelligence_indicator(
            str(indicator_data.get("type")),
            str(indicator_data.get("value")),
            source="provider",
            provider=str(finding.get("provider") or "unknown"),
            reputation=str(finding.get("reputation") or "unknown"),
            confidence=float(finding["confidence"]) if isinstance(finding.get("confidence"), (int, float)) else None,
            reference=str(finding["reference"]) if finding.get("reference") else None,
        )
        external_id = hashlib.sha256(
            f"{finding.get('provider')}|{indicator.indicator_type}|{indicator.normalized_value}|{finding.get('retrieved_at')}".encode()
        ).hexdigest()
        object_record = IntelligenceObject(
            organization_id=_current_organization_id(),
            object_type="provider_finding",
            name=f"{finding.get('provider')} finding for {indicator.indicator_type}",
            external_id=external_id,
            source=str(finding.get("provider") or "unknown"),
            reference=str(finding["reference"]) if finding.get("reference") else None,
            attributes=json.dumps(
                _safe_intelligence_attributes(
                    {
                        "reputation": finding.get("reputation"),
                        "summary": finding.get("summary"),
                        "attack_techniques": finding.get("attack_techniques", []),
                        **_safe_intelligence_attributes(finding.get("attributes")),
                    }
                ),
                default=str,
            ),
            verified=False,
            confidence=float(finding["confidence"]) if isinstance(finding.get("confidence"), (int, float)) else None,
            created_by_user_id=_current_user_id(),
        )
        existing = _db().session.scalar(
            select(IntelligenceObject).where(
                IntelligenceObject.organization_id == _current_organization_id(),
                IntelligenceObject.object_type == object_record.object_type,
                IntelligenceObject.source == object_record.source,
                IntelligenceObject.external_id == object_record.external_id,
            )
        )
        if existing is None:
            _db().session.add(object_record)
            _db().session.flush()
        else:
            object_record = existing
        _add_intelligence_relationship(
            source_kind="indicator",
            source_id=indicator.id,
            target_kind="intelligence_object",
            target_id=object_record.id,
            relationship_type="has_provider_finding",
            provenance=str(finding.get("provider") or "unknown"),
            reference=str(finding["reference"]) if finding.get("reference") else None,
            verified=False,
            confidence=object_record.confidence,
        )
    _db().session.commit()


def _indicator_json(item: IntelligenceIndicator) -> dict[str, object]:
    return {
        "id": str(item.id),
        "indicator_type": item.indicator_type,
        "value": item.normalized_value,
        "lifecycle_status": item.lifecycle_status,
        "reputation": item.reputation,
        "source": item.source,
        "provider": item.provider,
        "reference": item.reference,
        "confidence": item.confidence,
        "first_seen_at": item.first_seen_at.isoformat(),
        "last_seen_at": item.last_seen_at.isoformat(),
        "updated_at": item.updated_at.isoformat(),
    }


def _intelligence_object_json(item: IntelligenceObject) -> dict[str, object]:
    return {
        "id": str(item.id),
        "object_type": item.object_type,
        "name": item.name,
        "external_id": item.external_id,
        "source": item.source,
        "reference": item.reference,
        "attributes": _stored_json(item.attributes) or {},
        "verified": item.verified,
        "confidence": item.confidence,
        "first_seen_at": item.first_seen_at.isoformat() if item.first_seen_at else None,
        "last_seen_at": item.last_seen_at.isoformat() if item.last_seen_at else None,
        "updated_at": item.updated_at.isoformat(),
    }


@api_v1_blueprint.get("/intelligence-center")
def intelligence_center_workspace():  # type: ignore[no-untyped-def]
    organization_id = _current_organization_id()
    indicators = list(
        _db().session.scalars(
            select(IntelligenceIndicator)
            .where(IntelligenceIndicator.organization_id == organization_id)
            .order_by(IntelligenceIndicator.updated_at.desc())
        )
    )
    objects = list(
        _db().session.scalars(
            select(IntelligenceObject)
            .where(IntelligenceObject.organization_id == organization_id)
            .order_by(IntelligenceObject.updated_at.desc())
        )
    )
    relationships = list(
        _db().session.scalars(
            select(IntelligenceRelationship)
            .where(IntelligenceRelationship.organization_id == organization_id)
            .order_by(IntelligenceRelationship.created_at.desc())
        )
    )
    accessible_cases = _owned_case_ids()
    accessible_evidence = (
        set(_db().session.scalars(select(Evidence.id).where(Evidence.case_id.in_(accessible_cases))))
        if accessible_cases
        else set()
    )
    evidence_linked_indicator_ids = {
        item.source_id for item in relationships if item.source_kind == "indicator" and item.target_kind == "evidence"
    }
    accessible_linked_indicator_ids = {
        item.source_id
        for item in relationships
        if item.source_kind == "indicator" and item.target_kind == "evidence" and item.target_id in accessible_evidence
    }
    indicators = [
        item
        for item in indicators
        if item.id not in evidence_linked_indicator_ids or item.id in accessible_linked_indicator_ids
    ]
    visible_indicator_ids = {item.id for item in indicators}
    linked_object_indicator_ids: dict[UUID, set[UUID]] = {}
    for relationship in relationships:
        if relationship.source_kind == "indicator" and relationship.target_kind == "intelligence_object":
            linked_object_indicator_ids.setdefault(relationship.target_id, set()).add(relationship.source_id)
    objects = [
        item
        for item in objects
        if item.id not in linked_object_indicator_ids
        or bool(linked_object_indicator_ids[item.id] & visible_indicator_ids)
    ]
    visible_relationships = [
        item
        for item in relationships
        if not (
            (item.source_kind == "evidence" and item.source_id not in accessible_evidence)
            or (item.target_kind == "evidence" and item.target_id not in accessible_evidence)
        )
    ]
    indicator_ids = {item.id for item in indicators}
    object_ids = {item.id for item in objects}
    nodes = [
        {
            "id": f"indicator:{item.id}",
            "kind": "indicator",
            "label": f"{item.indicator_type}: {item.normalized_value}",
            "verified": item.source == "evidence",
        }
        for item in indicators
    ] + [
        {
            "id": f"intelligence_object:{item.id}",
            "kind": item.object_type,
            "label": item.name,
            "verified": item.verified,
        }
        for item in objects
    ]
    for evidence_id in sorted(
        {item.source_id for item in visible_relationships if item.source_kind == "evidence"}
        | {item.target_id for item in visible_relationships if item.target_kind == "evidence"},
        key=str,
    ):
        evidence = _db().session.get(Evidence, evidence_id)
        if evidence:
            nodes.append(
                {
                    "id": f"evidence:{evidence.id}",
                    "kind": "evidence",
                    "label": evidence.evidence_number,
                    "verified": True,
                }
            )
    edges = [
        {
            "id": str(item.id),
            "source": f"{item.source_kind}:{item.source_id}",
            "target": f"{item.target_kind}:{item.target_id}",
            "relationship_type": item.relationship_type,
            "provenance": item.provenance,
            "verified": item.verified,
            "confidence": item.confidence,
        }
        for item in visible_relationships
        if (item.source_kind != "indicator" or item.source_id in indicator_ids)
        and (item.target_kind != "indicator" or item.target_id in indicator_ids)
        and (item.source_kind != "intelligence_object" or item.source_id in object_ids)
        and (item.target_kind != "intelligence_object" or item.target_id in object_ids)
    ]
    related_case_ids: set[UUID] = set()
    for evidence_id in accessible_evidence:
        if not any(
            (item.source_kind == "evidence" and item.source_id == evidence_id)
            or (item.target_kind == "evidence" and item.target_id == evidence_id)
            for item in visible_relationships
        ):
            continue
        evidence = _db().session.get(Evidence, evidence_id)
        if evidence is None:
            continue
        related_case_ids.add(evidence.case_id)
        edges.append(
            {
                "id": f"derived:evidence-case:{evidence.id}",
                "source": f"evidence:{evidence.id}",
                "target": f"case:{evidence.case_id}",
                "relationship_type": "preserved_in",
                "provenance": "investigation_database",
                "verified": True,
                "confidence": None,
            }
        )
    for case_id in related_case_ids:
        case = _db().session.get(Case, case_id)
        if case:
            nodes.append(
                {"id": f"case:{case.id}", "kind": "investigation", "label": case.case_number, "verified": True}
            )
        for report in _db().session.scalars(select(Report).where(Report.case_id == case_id)):
            nodes.append({"id": f"report:{report.id}", "kind": "report", "label": report.title, "verified": True})
            edges.append(
                {
                    "id": f"derived:case-report:{report.id}",
                    "source": f"case:{case_id}",
                    "target": f"report:{report.id}",
                    "relationship_type": "documented_by",
                    "provenance": "report_database",
                    "verified": True,
                    "confidence": None,
                }
            )
        for timeline in _db().session.scalars(
            select(TimelineEvent)
            .where(TimelineEvent.case_id == case_id)
            .order_by(TimelineEvent.occurred_at.desc())
            .limit(50)
        ):
            nodes.append(
                {
                    "id": f"timeline_event:{timeline.id}",
                    "kind": "timeline_event",
                    "label": timeline.summary,
                    "verified": True,
                }
            )
            edges.append(
                {
                    "id": f"derived:case-timeline:{timeline.id}",
                    "source": f"case:{case_id}",
                    "target": f"timeline_event:{timeline.id}",
                    "relationship_type": "has_timeline_event",
                    "provenance": "timeline_database",
                    "verified": True,
                    "confidence": None,
                }
            )
    hunts = (
        list(
            _db().session.scalars(
                select(ThreatHunt).where(
                    ThreatHunt.organization_id == organization_id,
                    ThreatHunt.case_id.in_(related_case_ids),
                )
            )
        )
        if related_case_ids
        else []
    )
    hunt_ids = {item.id for item in hunts}
    for alert in (
        _db().session.scalars(
            select(DetectionAlert).where(
                DetectionAlert.organization_id == organization_id,
                DetectionAlert.hunt_id.in_(hunt_ids),
            )
        )
        if hunt_ids
        else []
    ):
        indicator = _db().session.scalar(
            select(IntelligenceIndicator).where(
                IntelligenceIndicator.organization_id == organization_id,
                IntelligenceIndicator.indicator_type == alert.indicator_type,
                IntelligenceIndicator.normalized_value == alert.indicator_value,
            )
        )
        if indicator is None:
            continue
        nodes.append(
            {"id": f"detection_alert:{alert.id}", "kind": "detection_alert", "label": alert.status, "verified": True}
        )
        edges.append(
            {
                "id": f"derived:indicator-alert:{alert.id}",
                "source": f"indicator:{indicator.id}",
                "target": f"detection_alert:{alert.id}",
                "relationship_type": "matched_detection",
                "provenance": "detection_engine",
                "verified": True,
                "confidence": None,
            }
        )
    return jsonify(
        {
            "intelligence_feed": [{"kind": "indicator", **_indicator_json(item)} for item in indicators]
            + [{"kind": "object", **_intelligence_object_json(item)} for item in objects],
            "ioc_search": {"stored_indicators": len(indicators)},
            "threat_actors": [
                _intelligence_object_json(item) for item in objects if item.object_type == "threat_actor"
            ],
            "campaigns": [_intelligence_object_json(item) for item in objects if item.object_type == "campaign"],
            "graph": {"nodes": nodes, "edges": edges},
            "providers": {
                "configured": list(_features().threat_intelligence.engine.provider_names),
                "available": bool(_features().threat_intelligence.engine.provider_names),
            },
            "sharing": UnavailableIntelligenceSharingAdapter().availability(),
        }
    )


@api_v1_blueprint.post("/intelligence-center/iocs/search")
def search_intelligence_ioc():  # type: ignore[no-untyped-def]
    data = request.get_json(silent=True) or {}
    try:
        normalized = normalize_indicator(str(data.get("indicator_type", "")), str(data.get("indicator_value", "")))
    except (KeyError, ValueError) as error:
        _intelligence_audit(
            "intelligence.ioc.searched",
            "indicator:invalid",
            "Indicator normalization failed.",
            result="failure",
        )
        _db().session.commit()
        return _json_error(str(error), 400)
    matches: list[dict[str, str]] = []
    for case_id in _owned_case_ids():
        _inventory, sources = _case_indicator_inventory(case_id)
        matches.extend(sources.get((normalized.type.value, normalized.value), []))
    stored = _upsert_intelligence_indicator(
        normalized.type.value,
        normalized.value,
        source="evidence" if matches else "analyst_search",
    )
    for match in matches:
        _add_intelligence_relationship(
            source_kind="indicator",
            source_id=stored.id,
            target_kind="evidence",
            target_id=UUID(match["evidence_id"]),
            relationship_type="observed_in",
            provenance="evidence_correlation",
            verified=True,
        )
    enrich = data.get("enrich") is True
    result = _features().threat_intelligence.engine.correlate([normalized]) if enrich else None
    if result:
        result["indicators"][0]["sources"] = matches
        _persist_intelligence_projection(
            _db().session.get(Evidence, UUID(matches[0]["evidence_id"])).case_id
            if matches
            else next(iter(_owned_case_ids()), UUID(int=0)),
            result,
        )
    _intelligence_audit(
        "intelligence.ioc.searched",
        f"indicator:{stored.id}",
        f"evidence_matches:{len(matches)}; enrichment:{enrich}; providers:{len(result.get('providers', [])) if result else 0}",
    )
    _db().session.commit()
    return jsonify(
        {
            "indicator": _indicator_json(stored),
            "evidence_matches": matches,
            "provider_result": result,
            "provider_status": (
                "not_requested"
                if not enrich
                else "unavailable"
                if not _features().threat_intelligence.engine.provider_names
                else "completed"
            ),
        }
    )


@api_v1_blueprint.post("/intelligence-center/objects")
def import_intelligence_object():  # type: ignore[no-untyped-def]
    data = request.get_json(silent=True) or {}
    object_type = str(data.get("object_type", "")).lower()
    allowed = {"threat_actor", "campaign", "malware", "cve", "attack_technique", "provider_finding"}
    if object_type not in allowed:
        return _json_error(f"object_type must be one of: {', '.join(sorted(allowed))}.", 400)
    name = _normalize_text(data.get("name"), limit=255)
    external_id = _normalize_text(data.get("external_id"), limit=255)
    source = _normalize_text(data.get("source"), limit=128)
    reference = _normalize_text(data.get("reference"), limit=2048)
    if not name or not external_id or not source or not reference:
        return _json_error("name, external_id, source, and reference are required.", 400)
    existing = _db().session.scalar(
        select(IntelligenceObject).where(
            IntelligenceObject.organization_id == _current_organization_id(),
            IntelligenceObject.object_type == object_type,
            IntelligenceObject.source == source,
            IntelligenceObject.external_id == external_id,
        )
    )
    if existing is not None:
        return _json_error("This sourced intelligence object already exists.", 409)
    item = IntelligenceObject(
        organization_id=_current_organization_id(),
        object_type=object_type,
        name=name,
        external_id=external_id,
        source=source,
        reference=reference,
        attributes=json.dumps(_safe_intelligence_attributes(data.get("attributes")), default=str),
        verified=data.get("verified") is True,
        confidence=float(data["confidence"]) if isinstance(data.get("confidence"), (int, float)) else None,
        created_by_user_id=_current_user_id(),
    )
    _db().session.add(item)
    _db().session.flush()
    _intelligence_audit("intelligence.object.imported", f"intelligence_object:{item.id}", f"source:{source}")
    _db().session.commit()
    return jsonify(_intelligence_object_json(item)), 201


@api_v1_blueprint.patch("/intelligence-center/iocs/<indicator_id>")
def update_indicator_lifecycle(indicator_id: str):  # type: ignore[no-untyped-def]
    try:
        item = _db().session.get(IntelligenceIndicator, _uuid(indicator_id, "indicator_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if item is None or item.organization_id != _current_organization_id():
        return _json_error("Indicator was not found.", 404)
    data = request.get_json(silent=True) or {}
    status = str(data.get("lifecycle_status", "")).lower()
    if status not in {"new", "active", "monitoring", "expired", "revoked", "false_positive"}:
        return _json_error("Invalid IOC lifecycle status.", 400)
    previous = item.lifecycle_status
    item.lifecycle_status = status
    item.updated_at = utc_now()
    _intelligence_audit("intelligence.ioc.lifecycle_updated", f"indicator:{item.id}", f"{previous}->{status}")
    _db().session.commit()
    return jsonify(_indicator_json(item))


@api_v1_blueprint.post("/intelligence-center/relationships")
def create_intelligence_relationship():  # type: ignore[no-untyped-def]
    data = request.get_json(silent=True) or {}
    try:
        source_id = _uuid(str(data.get("source_id", "")), "source_id")
        target_id = _uuid(str(data.get("target_id", "")), "target_id")
    except ValueError as error:
        return _json_error(str(error), 400)
    source_kind = str(data.get("source_kind", ""))
    target_kind = str(data.get("target_kind", ""))
    allowed_kinds = {"indicator", "intelligence_object"}
    if source_kind not in allowed_kinds or target_kind not in allowed_kinds:
        return _json_error("Manual relationships may connect indicators and intelligence objects only.", 400)
    source_model = IntelligenceIndicator if source_kind == "indicator" else IntelligenceObject
    target_model = IntelligenceIndicator if target_kind == "indicator" else IntelligenceObject
    source = _db().session.get(source_model, source_id)
    target = _db().session.get(target_model, target_id)
    if (
        source is None
        or target is None
        or source.organization_id != _current_organization_id()
        or target.organization_id != _current_organization_id()
    ):
        return _json_error("Relationship objects were not found.", 404)
    relationship_type = re.sub(r"[^a-z0-9_.-]", "_", str(data.get("relationship_type", "")).lower())[:64]
    reference = _normalize_text(data.get("reference"), limit=2048)
    if not relationship_type or not reference:
        return _json_error("relationship_type and reference are required.", 400)
    relationship = _add_intelligence_relationship(
        source_kind=source_kind,
        source_id=source_id,
        target_kind=target_kind,
        target_id=target_id,
        relationship_type=relationship_type,
        provenance="analyst_import",
        reference=reference,
        verified=data.get("verified") is True,
    )
    _intelligence_audit(
        "intelligence.relationship.created",
        f"intelligence_relationship:{relationship.id}",
        f"type:{relationship_type}",
    )
    _db().session.commit()
    return jsonify({"id": str(relationship.id), "relationship_type": relationship.relationship_type}), 201


@api_v1_blueprint.post("/intelligence-center/ai-summary")
def intelligence_ai_summary():  # type: ignore[no-untyped-def]
    indicators = list(
        _db().session.scalars(
            select(IntelligenceIndicator)
            .where(IntelligenceIndicator.organization_id == _current_organization_id())
            .order_by(IntelligenceIndicator.updated_at.desc())
            .limit(50)
        )
    )
    objects = list(
        _db().session.scalars(
            select(IntelligenceObject)
            .where(IntelligenceObject.organization_id == _current_organization_id())
            .order_by(IntelligenceObject.updated_at.desc())
            .limit(50)
        )
    )
    summary = _ai_completion(
        "Summarize only the supplied intelligence records. Separate evidence observations, provider assertions, and analyst imports. Do not infer threat actors, campaigns, malware, CVEs, relationships, or confidence.",
        {
            "indicators": [
                {
                    "type": item.indicator_type,
                    "lifecycle": item.lifecycle_status,
                    "reputation": item.reputation,
                    "source": item.source,
                    "provider": item.provider,
                }
                for item in indicators
            ],
            "objects": [
                {
                    "type": item.object_type,
                    "name": item.name,
                    "source": item.source,
                    "verified": item.verified,
                }
                for item in objects
            ],
        },
    )
    _intelligence_audit(
        "intelligence.ai_summary.requested",
        "intelligence:center",
        f"indicators:{len(indicators)}; objects:{len(objects)}",
    )
    _db().session.commit()
    return jsonify(
        {
            "provenance": "ai_generated_observation",
            "verified_intelligence": False,
            "summary": summary,
        }
    )


def _hunt_accessible(hunt: ThreatHunt | None) -> bool:
    return bool(
        hunt is not None and hunt.organization_id == _current_organization_id() and _case_accessible(hunt.case_id)
    )


def _hunt_audit(
    action: str,
    affected_object: str,
    reason: str | None = None,
    *,
    result: str = "success",
) -> None:
    _db().session.add(
        AuditLog(
            organization_id=_current_organization_id(),
            user_id=_current_user_id(),
            username=_current_username(),
            role=_current_user_role(),
            action=action,
            result=result,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            affected_object=affected_object,
            reason=reason,
        )
    )


def _hunt_json(hunt: ThreatHunt) -> dict[str, object]:
    case = _db().session.get(Case, hunt.case_id)
    return {
        "id": str(hunt.id),
        "case_id": str(hunt.case_id),
        "case_number": case.case_number if case else None,
        "name": hunt.name,
        "hypothesis": hunt.hypothesis,
        "scope": hunt.scope,
        "status": hunt.status,
        "owner_user_id": str(hunt.owner_user_id) if hunt.owner_user_id else None,
        "started_at": hunt.started_at.isoformat() if hunt.started_at else None,
        "completed_at": hunt.completed_at.isoformat() if hunt.completed_at else None,
        "created_at": hunt.created_at.isoformat(),
        "updated_at": hunt.updated_at.isoformat(),
    }


def _rule_json(rule: DetectionRule) -> dict[str, object]:
    return {
        "id": str(rule.id),
        "rule_key": rule.rule_key,
        "version": rule.version,
        "title": rule.title,
        "status": rule.status,
        "rule_format": rule.rule_format,
        "definition": _stored_json(rule.definition) or {},
        "attack_techniques": _stored_json(rule.attack_techniques) or [],
        "enabled": rule.enabled,
        "created_at": rule.created_at.isoformat(),
        "updated_at": rule.updated_at.isoformat(),
    }


def _validated_sigma(document: object) -> tuple[dict[str, object], list[str]]:
    if not isinstance(document, dict):
        raise ValueError("definition must be a Sigma-compatible JSON object.")
    if not isinstance(document.get("title"), str) or not str(document["title"]).strip():
        raise ValueError("Sigma title is required.")
    if not isinstance(document.get("logsource"), dict):
        raise ValueError("Sigma logsource must be an object.")
    detection = document.get("detection")
    if not isinstance(detection, dict) or not isinstance(detection.get("condition"), str):
        raise ValueError("Sigma detection and condition are required.")
    techniques: list[str] = []
    tags = document.get("tags", [])
    if tags is not None and not isinstance(tags, list):
        raise ValueError("Sigma tags must be a list.")
    for tag in tags or []:
        match = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", str(tag).lower())
        if match:
            techniques.append(match.group(1).upper())
    return document, sorted(set(techniques))


def _search_json(item: HuntIOCSearch) -> dict[str, object]:
    return {
        "id": str(item.id),
        "hunt_id": str(item.hunt_id),
        "indicator_type": item.indicator_type,
        "indicator_value": item.indicator_value,
        "evidence_matches": item.evidence_matches,
        "provider_findings": item.provider_findings,
        "provider_status": item.provider_status,
        "created_at": item.created_at.isoformat(),
    }


@api_v1_blueprint.get("/threat-hunting")
def threat_hunting_workspace():  # type: ignore[no-untyped-def]
    case_ids = _owned_case_ids()
    hunts = (
        list(
            _db().session.scalars(
                select(ThreatHunt)
                .where(
                    ThreatHunt.organization_id == _current_organization_id(),
                    ThreatHunt.case_id.in_(case_ids),
                )
                .order_by(ThreatHunt.updated_at.desc())
            )
        )
        if case_ids
        else []
    )
    hunt_ids = {item.id for item in hunts}
    searches = (
        list(
            _db().session.scalars(
                select(HuntIOCSearch)
                .where(HuntIOCSearch.hunt_id.in_(hunt_ids))
                .order_by(HuntIOCSearch.created_at.desc())
                .limit(100)
            )
        )
        if hunt_ids
        else []
    )
    alerts = (
        list(
            _db().session.scalars(
                select(DetectionAlert)
                .where(
                    DetectionAlert.organization_id == _current_organization_id(),
                    DetectionAlert.hunt_id.in_(hunt_ids),
                )
                .order_by(DetectionAlert.created_at.desc())
                .limit(100)
            )
        )
        if hunt_ids
        else []
    )
    rules = list(
        _db().session.scalars(
            select(DetectionRule)
            .where(DetectionRule.organization_id == _current_organization_id())
            .order_by(DetectionRule.updated_at.desc())
        )
    )
    coverage = sorted(
        {
            technique
            for rule in rules
            if rule.enabled and rule.status != "deprecated"
            for technique in (_stored_json(rule.attack_techniques) or [])
            if isinstance(technique, str)
        }
    )
    return jsonify(
        {
            "active_hunts": [_hunt_json(item) for item in hunts if item.status in {"draft", "active", "paused"}],
            "hunt_history": [_hunt_json(item) for item in hunts],
            "ioc_searches": [_search_json(item) for item in searches],
            "detection_alerts": [
                {
                    "id": str(item.id),
                    "hunt_id": str(item.hunt_id),
                    "rule_id": str(item.rule_id),
                    "evidence_id": str(item.evidence_id),
                    "indicator_type": item.indicator_type,
                    "indicator_value": item.indicator_value,
                    "source": item.source,
                    "status": item.status,
                    "created_at": item.created_at.isoformat(),
                }
                for item in alerts
            ],
            "attack_coverage": coverage,
            "detection_rules": [_rule_json(item) for item in rules],
            "provider_status": {
                "providers": list(_features().threat_intelligence.engine.provider_names),
                "available": bool(_features().threat_intelligence.engine.provider_names),
            },
        }
    )


@api_v1_blueprint.post("/threat-hunting/hunts")
def create_threat_hunt():  # type: ignore[no-untyped-def]
    data = request.get_json(silent=True) or {}
    try:
        case_id = _uuid(str(data.get("case_id", "")), "case_id")
    except ValueError as error:
        return _json_error(str(error), 400)
    if not _case_accessible(case_id):
        return _forbidden()
    name = _normalize_text(data.get("name"), limit=255)
    hypothesis = _normalize_text(data.get("hypothesis"), limit=20_000)
    if not name or not hypothesis:
        return _json_error("name and hypothesis are required.", 400)
    hunt = ThreatHunt(
        organization_id=_current_organization_id(),
        case_id=case_id,
        name=name,
        hypothesis=hypothesis,
        scope=_normalize_text(data.get("scope"), limit=20_000),
        owner_user_id=_current_user_id(),
    )
    _db().session.add(hunt)
    _db().session.flush()
    _hunt_audit("threat_hunt.created", f"hunt:{hunt.id}", f"case:{case_id}")
    _db().session.commit()
    return jsonify(_hunt_json(hunt)), 201


@api_v1_blueprint.patch("/threat-hunting/hunts/<hunt_id>")
def update_threat_hunt(hunt_id: str):  # type: ignore[no-untyped-def]
    try:
        hunt = _db().session.get(ThreatHunt, _uuid(hunt_id, "hunt_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if not _hunt_accessible(hunt):
        return _json_error("Hunt was not found.", 404)
    data = request.get_json(silent=True) or {}
    status = str(data.get("status", hunt.status)).lower()
    transitions = {
        "draft": {"active", "cancelled"},
        "active": {"paused", "completed", "cancelled"},
        "paused": {"active", "completed", "cancelled"},
        "completed": set(),
        "cancelled": set(),
    }
    if status != hunt.status and status not in transitions.get(hunt.status, set()):
        return _json_error(f"Cannot transition hunt from {hunt.status} to {status}.", 409)
    previous = hunt.status
    hunt.status = status
    if status == "active" and hunt.started_at is None:
        hunt.started_at = utc_now()
    hunt.completed_at = utc_now() if status == "completed" else hunt.completed_at
    hunt.updated_at = utc_now()
    if status != previous:
        _timeline_service().record_investigation_event(
            case_id=hunt.case_id,
            event_type=f"threat_hunt.{status}",
            summary=f"Hunt {hunt.name} moved to {status}",
            details=f"Recorded hunt lifecycle transition {previous} to {status}.",
        )
    _hunt_audit("threat_hunt.updated", f"hunt:{hunt.id}", f"{previous}->{status}")
    _db().session.commit()
    return jsonify(_hunt_json(hunt))


@api_v1_blueprint.post("/threat-hunting/hunts/<hunt_id>/ioc-searches")
def search_hunt_ioc(hunt_id: str):  # type: ignore[no-untyped-def]
    try:
        hunt = _db().session.get(ThreatHunt, _uuid(hunt_id, "hunt_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if not _hunt_accessible(hunt):
        return _json_error("Hunt was not found.", 404)
    data = request.get_json(silent=True) or {}
    try:
        indicator = normalize_indicator(str(data.get("indicator_type", "")), str(data.get("indicator_value", "")))
    except (KeyError, ValueError) as error:
        _hunt_audit(
            "threat_hunt.ioc_searched",
            f"hunt:{hunt.id}",
            f"type:{str(data.get('indicator_type', ''))[:32]}; validation_failed",
            result="failure",
        )
        _db().session.commit()
        return _json_error(str(error), 400)
    _inventory, sources = _case_indicator_inventory(hunt.case_id)
    key = (indicator.type.value, indicator.value)
    matched_sources = sources.get(key, [])
    enrich = data.get("enrich") is True
    engine = _features().threat_intelligence.engine
    intelligence = engine.correlate([indicator]) if enrich else None
    provider_findings = len(intelligence.get("findings", [])) if intelligence else 0
    provider_status = (
        "not_requested"
        if not enrich
        else "unavailable"
        if not engine.provider_names
        else "completed_with_errors"
        if intelligence and intelligence.get("errors")
        else "completed"
    )
    search = HuntIOCSearch(
        organization_id=_current_organization_id(),
        hunt_id=hunt.id,
        actor_user_id=_current_user_id(),
        indicator_type=indicator.type.value,
        indicator_value=indicator.value,
        evidence_matches=len(matched_sources),
        provider_findings=provider_findings,
        provider_status=provider_status,
    )
    _db().session.add(search)
    _db().session.flush()
    for source in matched_sources:
        _db().session.add(
            HuntCorrelation(
                organization_id=_current_organization_id(),
                hunt_id=hunt.id,
                search_id=search.id,
                evidence_id=UUID(source["evidence_id"]),
                indicator_type=indicator.type.value,
                indicator_value=indicator.value,
                source="verified_evidence",
            )
        )
    _hunt_audit(
        "threat_hunt.ioc_searched",
        f"hunt:{hunt.id}",
        f"type:{indicator.type.value}; evidence_matches:{len(matched_sources)}; provider_status:{provider_status}",
    )
    _db().session.commit()
    return jsonify(
        {
            **_search_json(search),
            "correlations": matched_sources,
            "intelligence": intelligence,
            "explainability": "Evidence matches are verified stored observations; provider findings are external assertions.",
        }
    )


@api_v1_blueprint.get("/detection-rules")
def list_detection_rules():  # type: ignore[no-untyped-def]
    rules = _db().session.scalars(
        select(DetectionRule)
        .where(DetectionRule.organization_id == _current_organization_id())
        .order_by(DetectionRule.rule_key, DetectionRule.version.desc())
    )
    return jsonify({"items": [_rule_json(item) for item in rules]})


@api_v1_blueprint.post("/detection-rules")
def create_detection_rule():  # type: ignore[no-untyped-def]
    data = request.get_json(silent=True) or {}
    rule_key = re.sub(r"[^a-z0-9_.-]", "-", str(data.get("rule_key", "")).strip().lower())[:128].strip("-")
    if not rule_key:
        return _json_error("rule_key is required.", 400)
    try:
        definition, techniques = _validated_sigma(data.get("definition"))
    except ValueError as error:
        return _json_error(str(error), 400)
    latest = _db().session.scalar(
        select(func.max(DetectionRule.version)).where(
            DetectionRule.organization_id == _current_organization_id(),
            DetectionRule.rule_key == rule_key,
        )
    )
    rule = DetectionRule(
        organization_id=_current_organization_id(),
        rule_key=rule_key,
        version=int(latest or 0) + 1,
        title=str(definition["title"])[:255],
        status=str(data.get("status", "experimental")).lower(),
        definition=json.dumps(definition, sort_keys=True),
        attack_techniques=json.dumps(techniques),
        enabled=data.get("enabled") is True,
        created_by_user_id=_current_user_id(),
    )
    if rule.status not in {"experimental", "test", "stable", "deprecated"}:
        return _json_error("Invalid detection rule status.", 400)
    _db().session.add(rule)
    _db().session.flush()
    _hunt_audit("detection_rule.created", f"detection_rule:{rule.id}", f"{rule_key}; version:{rule.version}")
    _db().session.commit()
    return jsonify(_rule_json(rule)), 201


@api_v1_blueprint.patch("/detection-rules/<rule_id>")
def update_detection_rule(rule_id: str):  # type: ignore[no-untyped-def]
    try:
        rule = _db().session.get(DetectionRule, _uuid(rule_id, "rule_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if rule is None or rule.organization_id != _current_organization_id():
        return _json_error("Detection rule was not found.", 404)
    data = request.get_json(silent=True) or {}
    if "enabled" in data:
        rule.enabled = data["enabled"] is True
    if "status" in data:
        status = str(data["status"]).lower()
        if status not in {"experimental", "test", "stable", "deprecated"}:
            return _json_error("Invalid detection rule status.", 400)
        rule.status = status
    rule.updated_at = utc_now()
    _hunt_audit("detection_rule.updated", f"detection_rule:{rule.id}", f"enabled:{rule.enabled}; status:{rule.status}")
    _db().session.commit()
    return jsonify(_rule_json(rule))


def _rule_indicator_selection(rule: DetectionRule) -> list[object] | None:
    definition = _stored_json(rule.definition)
    if not isinstance(definition, dict):
        return None
    detection = definition.get("detection")
    if not isinstance(detection, dict) or detection.get("condition") != "selection":
        return None
    selection = detection.get("selection")
    if not isinstance(selection, dict):
        return None
    indicators = selection.get("indicator")
    return indicators if isinstance(indicators, list) else None


@api_v1_blueprint.post("/detection-rules/<rule_id>/evaluate")
def evaluate_detection_rule(rule_id: str):  # type: ignore[no-untyped-def]
    try:
        rule = _db().session.get(DetectionRule, _uuid(rule_id, "rule_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if rule is None or rule.organization_id != _current_organization_id():
        return _json_error("Detection rule was not found.", 404)
    data = request.get_json(silent=True) or {}
    try:
        hunt = _db().session.get(ThreatHunt, _uuid(str(data.get("hunt_id", "")), "hunt_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if not _hunt_accessible(hunt):
        return _json_error("Hunt was not found.", 404)
    if not rule.enabled:
        return _json_error("Detection rule is disabled.", 409)
    selection = _rule_indicator_selection(rule)
    if selection is None:
        return _json_error("This Sigma rule uses unsupported evaluation semantics.", 409)
    _inventory, sources = _case_indicator_inventory(hunt.case_id)
    matches: list[dict[str, str]] = []
    for item in selection:
        if not isinstance(item, dict) or not item.get("type") or not item.get("value"):
            continue
        try:
            indicator = normalize_indicator(str(item["type"]), str(item["value"]))
        except (KeyError, ValueError):
            continue
        for source in sources.get((indicator.type.value, indicator.value), []):
            existing = _db().session.scalar(
                select(DetectionAlert.id).where(
                    DetectionAlert.hunt_id == hunt.id,
                    DetectionAlert.rule_id == rule.id,
                    DetectionAlert.evidence_id == UUID(source["evidence_id"]),
                    DetectionAlert.indicator_type == indicator.type.value,
                    DetectionAlert.indicator_value == indicator.value,
                )
            )
            if existing is None:
                alert = DetectionAlert(
                    organization_id=_current_organization_id(),
                    hunt_id=hunt.id,
                    rule_id=rule.id,
                    evidence_id=UUID(source["evidence_id"]),
                    indicator_type=indicator.type.value,
                    indicator_value=indicator.value,
                )
                _db().session.add(alert)
            matches.append({**source, "indicator_type": indicator.type.value, "indicator_value": indicator.value})
    _hunt_audit(
        "detection_rule.evaluated",
        f"detection_rule:{rule.id}",
        f"hunt:{hunt.id}; verified_matches:{len(matches)}",
    )
    if matches:
        _timeline_service().record_investigation_event(
            case_id=hunt.case_id,
            event_type="detection_rule.matched",
            summary=f"Detection rule {rule.title} matched {len(matches)} stored observation(s)",
            details=f"Rule {rule.rule_key} v{rule.version}; verified evidence observations only.",
        )
    _db().session.commit()
    return jsonify(
        {
            "rule_id": str(rule.id),
            "hunt_id": str(hunt.id),
            "status": "completed",
            "verified_matches": matches,
            "match_count": len(matches),
            "execution_semantics": "indicator_match_v1",
        }
    )


@api_v1_blueprint.post("/threat-hunting/hunts/<hunt_id>/ai-recommendations")
def hunt_ai_recommendations(hunt_id: str):  # type: ignore[no-untyped-def]
    try:
        hunt = _db().session.get(ThreatHunt, _uuid(hunt_id, "hunt_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if not _hunt_accessible(hunt):
        return _json_error("Hunt was not found.", 404)
    indicators, _sources = _case_indicator_inventory(hunt.case_id)
    intelligence = _threat_intelligence_projection(hunt.case_id, enrich=False)
    suggestion = _ai_completion(
        "Suggest threat-hunting next steps using only the supplied hypothesis, observed indicator types, and recorded ATT&CK mappings. Do not assert detections, threat actors, malware, or provider findings.",
        {
            "hypothesis": hunt.hypothesis,
            "scope": hunt.scope,
            "observed_indicator_types": sorted({item.type.value for item in indicators}),
            "recorded_attack_mappings": intelligence.get("attack_mappings", []),
        },
    )
    _hunt_audit("threat_hunt.ai_recommendations.requested", f"hunt:{hunt.id}", "AI suggestions are non-verified.")
    _db().session.commit()
    return jsonify(
        {
            "hunt_id": str(hunt.id),
            "provenance": "ai_generated_suggestion",
            "verified_finding": False,
            "suggestion": suggestion,
        }
    )


@api_v1_blueprint.get("/evidence")
def list_evidence():  # type: ignore[no-untyped-def]
    session = _db().session
    statement = select(Evidence).where(Evidence.deleted_at.is_(None))
    case_id = request.args.get("case_id")
    if case_id:
        try:
            statement = statement.where(Evidence.case_id == _uuid(case_id, "case_id"))
        except ValueError as error:
            return _json_error(str(error), 400)
    owned_ids = _owned_case_ids()
    if not owned_ids:
        return jsonify(_page([], total=0))
    statement = statement.where(Evidence.case_id.in_(owned_ids))
    items = [_evidence_json(item) for item in session.scalars(statement)]
    query = _query_text()
    analysis_status = request.args.get("analysis_status", "all")
    if query:
        items = [
            item
            for item in items
            if query in item["evidence_number"].lower()
            or query in item["original_filename"].lower()
            or query in (item["source_description"] or "").lower()
            or query in item["sha256"].lower()
            or query in (item["analysis_summary"] or "").lower()
        ]
    if analysis_status != "all":
        items = [item for item in items if item["analysis_status"] == analysis_status]
    sort = _sort_key(
        "acquired_at", {"evidence_number", "original_filename", "size_bytes", "acquired_at", "analysis_status"}
    )
    items.sort(key=lambda item: item.get(sort) or "", reverse=_direction() == "desc")
    return jsonify(_page(items, total=len(items)))


@api_v1_blueprint.post("/evidence")
def create_evidence():  # type: ignore[no-untyped-def]
    try:
        if request.files:
            upload = request.files.get("file")
            if upload is None:
                return _json_error("A file field is required.", 400)
            content = upload.stream
            filename = upload.filename or "evidence.bin"
            media_type = upload.mimetype
            case_id = request.form.get("case_id", "")
            evidence_number = request.form.get("evidence_number", "")
            source_description = request.form.get("source_description")
        else:
            data = request.get_json(silent=True) or {}
            content = BytesIO(str(data.get("content", "")).encode("utf-8"))
            filename = str(data.get("filename", "evidence.txt"))
            media_type = str(data.get("media_type", "text/plain"))
            case_id = str(data.get("case_id", ""))
            evidence_number = str(data.get("evidence_number", ""))
            source_description = data.get("source_description")
        parsed_case_id = _uuid(case_id, "case_id")
        if not _case_accessible(parsed_case_id):
            return _forbidden()
        created = _evidence_service().add_evidence(
            EvidenceAddRequest(
                case_id=parsed_case_id,
                evidence_number=evidence_number,
                filename=filename,
                content=content,
                media_type=media_type,
                source_description=source_description,
            )
        )
        _timeline_service().record_evidence_event(
            case_id=created.case_id,
            evidence_id=created.id,
            event_type="evidence.added",
            summary=f"Evidence {created.evidence_number} added",
            details=created.original_filename,
        )
        _stamp_case_children(created.case_id)
        evidence_record = _db().session.get(Evidence, created.id)
        if evidence_record is not None:
            _append_custody_event(
                evidence_record,
                "evidence.quarantined",
                details=f"size_bytes:{evidence_record.size_bytes}; sha256_verified_at_ingest:true",
            )
            _record_evidence_audit("evidence.ingested", evidence_record)
        _invalidate_dashboard_cache()
        return jsonify(_evidence_json(evidence_record)), 201
    except (ValueError, CaseManagementError, EvidenceManagementError) as error:
        return _json_error(str(error), 400)


@api_v1_blueprint.delete("/evidence/<evidence_id>")
def delete_evidence(evidence_id: str):  # type: ignore[no-untyped-def]
    try:
        evidence = _db().session.get(Evidence, _uuid(evidence_id, "evidence_id"))
        if evidence is None or not _case_accessible(evidence.case_id):
            return _forbidden()
        if _case_has_legal_hold(evidence.case_id):
            return _json_error("Evidence is protected by an active investigation legal hold.", 409)
        deleted = _evidence_service().delete_evidence(_uuid(evidence_id, "evidence_id"))
        _timeline_service().record_evidence_event(
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            event_type="evidence.soft_deleted",
            summary=f"Evidence {evidence.evidence_number} removed from active inventory",
            details="Custody bytes were retained; metadata was soft-deleted.",
        )
        _append_custody_event(evidence, "evidence.soft_deleted", details="Custody bytes retained.")
        _record_evidence_audit("evidence.soft_deleted", evidence)
        _invalidate_dashboard_cache()
        return jsonify(_evidence_json(deleted))
    except (ValueError, EvidenceManagementError) as error:
        return _json_error(str(error), 400)


@api_v1_blueprint.get("/evidence/<evidence_id>/analysis")
def evidence_analysis(evidence_id: str):  # type: ignore[no-untyped-def]
    """Return analysis for one evidence record without requiring UI payload construction."""
    try:
        evidence = _db().session.get(Evidence, _uuid(evidence_id, "evidence_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if evidence is None or not _case_accessible(evidence.case_id):
        return _forbidden()
    return _analyze_evidence_record(evidence_id)


@api_v1_blueprint.post("/evidence/<evidence_id>/analysis-jobs")
def start_evidence_analysis(evidence_id: str):  # type: ignore[no-untyped-def]
    """Queue evidence analysis and immediately return progress metadata."""
    try:
        evidence = _db().session.get(Evidence, _uuid(evidence_id, "evidence_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if evidence is None or not _case_accessible(evidence.case_id):
        return _forbidden()
    if evidence.analysis_status == "running":
        return _json_error("Evidence analysis is already running.", 409)
    evidence.analysis_status = "running"
    _append_custody_event(evidence, "evidence.analysis.queued", details="execution:non_executing_static")
    _db().session.commit()
    _record_evidence_audit("evidence.analysis.queued", evidence)
    job = _start_evidence_analysis_job(evidence_id)
    return jsonify(job), 202


@api_v1_blueprint.get("/evidence/analysis-jobs/<job_id>")
def evidence_analysis_job(job_id: str):  # type: ignore[no-untyped-def]
    """Return current progress for an evidence-analysis background job."""
    job = _analysis_jobs().get(job_id)
    if job is None:
        return _json_error("Analysis job was not found.", 404)
    try:
        evidence = _db().session.get(Evidence, _uuid(str(job.get("evidence_id")), "evidence_id"))
    except ValueError:
        return _json_error("Analysis job was not found.", 404)
    if evidence is None or not _case_accessible(evidence.case_id):
        return _forbidden()
    return jsonify(job)


def _analysis_run_json(run: EvidenceAnalysisRun) -> dict[str, object]:
    return {
        "id": str(run.id),
        "evidence_id": str(run.evidence_id),
        "analyzer": run.analyzer,
        "analyzer_version": run.analyzer_version,
        "status": run.status,
        "evidence_sha256": run.evidence_sha256,
        "integrity_verified": run.integrity_verified,
        "modules": _stored_json(run.module_manifest) or [],
        "error_code": run.error_code,
        "created_at": run.created_at.isoformat(),
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
    }


@api_v1_blueprint.get("/evidence-lab")
def evidence_lab_workspace():  # type: ignore[no-untyped-def]
    """Return tenant- and case-access-scoped laboratory records."""
    case_ids = _owned_case_ids()
    if not case_ids:
        return jsonify(
            {
                "evidence_status": [],
                "analysis_results": [],
                "queue": [],
                "artifacts": [],
                "sandbox": UnavailableSandboxAdapter().availability(),
            }
        )
    session = _db().session
    evidence_rows = list(
        session.scalars(
            select(Evidence)
            .where(Evidence.case_id.in_(case_ids), Evidence.deleted_at.is_(None))
            .order_by(Evidence.acquired_at.desc())
        )
    )
    evidence_ids = {item.id for item in evidence_rows}
    runs = (
        list(
            session.scalars(
                select(EvidenceAnalysisRun)
                .where(
                    EvidenceAnalysisRun.organization_id == _current_organization_id(),
                    EvidenceAnalysisRun.evidence_id.in_(evidence_ids),
                )
                .order_by(EvidenceAnalysisRun.created_at.desc())
            )
        )
        if evidence_ids
        else []
    )
    artifacts = (
        list(
            session.scalars(
                select(Artifact).where(Artifact.evidence_id.in_(evidence_ids)).order_by(Artifact.created_at.desc())
            )
        )
        if evidence_ids
        else []
    )
    queue = [
        {
            "id": item.get("id"),
            "evidence_id": item.get("evidence_id"),
            "status": item.get("status"),
            "progress": item.get("progress"),
            "step": item.get("step"),
        }
        for item in _analysis_jobs().values()
        if item.get("type") == "evidence_analysis"
        and item.get("evidence_id") in {str(identifier) for identifier in evidence_ids}
        and item.get("status") in {"queued", "running"}
    ]
    return jsonify(
        {
            "evidence_status": [
                {
                    "id": str(item.id),
                    "case_id": str(item.case_id),
                    "evidence_number": item.evidence_number,
                    "filename": item.original_filename,
                    "status": item.status,
                    "analysis_status": item.analysis_status,
                    "sha256": item.sha256,
                    "storage_state": "quarantined",
                }
                for item in evidence_rows
            ],
            "analysis_results": [_analysis_run_json(item) for item in runs],
            "queue": queue,
            "artifacts": [
                {
                    "id": str(item.id),
                    "evidence_id": str(item.evidence_id),
                    "analysis_run_id": str(item.analysis_run_id) if item.analysis_run_id else None,
                    "name": item.name,
                    "artifact_type": item.artifact_type,
                    "source_location": item.source_location,
                    "content_hash": item.content_hash,
                }
                for item in artifacts
            ],
            "sandbox": UnavailableSandboxAdapter().availability(),
        }
    )


@api_v1_blueprint.get("/evidence/<evidence_id>/lab")
def evidence_lab_record(evidence_id: str):  # type: ignore[no-untyped-def]
    try:
        evidence = _db().session.get(Evidence, _uuid(evidence_id, "evidence_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if evidence is None or not _case_accessible(evidence.case_id):
        return _forbidden()
    runs = list(
        _db().session.scalars(
            select(EvidenceAnalysisRun)
            .where(
                EvidenceAnalysisRun.organization_id == _current_organization_id(),
                EvidenceAnalysisRun.evidence_id == evidence.id,
            )
            .order_by(EvidenceAnalysisRun.created_at.desc())
        )
    )
    findings = list(
        _db().session.scalars(
            select(ForensicFinding)
            .where(
                ForensicFinding.organization_id == _current_organization_id(),
                ForensicFinding.evidence_id == evidence.id,
            )
            .order_by(ForensicFinding.created_at.desc())
        )
    )
    custody = list(
        _db().session.scalars(
            select(CustodyEvent)
            .where(
                CustodyEvent.organization_id == _current_organization_id(),
                CustodyEvent.evidence_id == evidence.id,
            )
            .order_by(CustodyEvent.occurred_at)
        )
    )
    return jsonify(
        {
            "evidence": _evidence_json(evidence),
            "analysis_runs": [_analysis_run_json(item) for item in runs],
            "verified_findings": [
                {
                    "id": str(item.id),
                    "analysis_run_id": str(item.analysis_run_id),
                    "finding_type": item.finding_type,
                    "value": item.value,
                    "source": item.source,
                    "verified_observation": item.verified_observation,
                }
                for item in findings
            ],
            "custody": [
                {
                    "id": str(item.id),
                    "event_type": item.event_type,
                    "evidence_sha256": item.evidence_sha256,
                    "storage_state": item.storage_state,
                    "details": item.details,
                    "occurred_at": item.occurred_at.isoformat(),
                }
                for item in custody
            ],
            "sandbox": UnavailableSandboxAdapter().availability(),
        }
    )


@api_v1_blueprint.get("/evidence/export")
def export_evidence():  # type: ignore[no-untyped-def]
    response = list_evidence()
    data = response.get_json()
    _db().session.add(
        AuditLog(
            user_id=_current_user_id(),
            username=_current_username(),
            role=_current_user_role(),
            action="evidence.inventory.exported",
            result="success",
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            affected_object="evidence:inventory",
            reason=f"{len(data['items'])} ownership-scoped record(s)",
        )
    )
    _db().session.commit()
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ["id", "case_id", "evidence_number", "filename", "media_type", "size_bytes", "sha256", "acquired_at"]
    )
    for item in data["items"]:
        writer.writerow(
            [
                item["id"],
                item["case_id"],
                item["evidence_number"],
                item["original_filename"],
                item["media_type"] or "",
                item["size_bytes"],
                item["sha256"],
                item["acquired_at"],
            ]
        )
    return Response(
        output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=evidence.csv"}
    )


@api_v1_blueprint.get("/timeline")
def list_timeline():  # type: ignore[no-untyped-def]
    statement = select(TimelineEvent)
    case_id = request.args.get("case_id")
    if case_id:
        try:
            statement = statement.where(TimelineEvent.case_id == _uuid(case_id, "case_id"))
        except ValueError as error:
            return _json_error(str(error), 400)
    owned_ids = _owned_case_ids()
    if not owned_ids:
        return jsonify(
            {
                **_page([], total=0),
                "correlations": {"cases": [], "evidence": [], "groups": {}, "confirmed": 0},
                "reconstruction": _features().timeline.reconstruction.reconstruct([]),
            }
        )
    statement = statement.where(TimelineEvent.case_id.in_(owned_ids))
    event_type = request.args.get("event_type", "all")
    if event_type != "all":
        statement = statement.where(TimelineEvent.event_type == event_type)
    group = request.args.get("group", "all")
    threat = request.args.get("threat", "all")
    items = [_timeline_json(item) for item in _db().session.scalars(statement)]
    query = _query_text()
    if query:
        items = [
            item
            for item in items
            if query in item["event_type"].lower()
            or query in item["summary"].lower()
            or query in (item["details"] or "").lower()
        ]
    if group != "all":
        items = [item for item in items if item["group"] == group]
    if threat != "all":
        items = [item for item in items if item["threat_level"] == threat]
    items.sort(key=lambda item: item["occurred_at"] or "", reverse=_direction() == "desc")
    payload = _page(items, total=len(items))
    evidence_ids = {_uuid(str(item["evidence_id"]), "evidence_id") for item in items if item.get("evidence_id")}
    evidence_reports = {
        str(record.id): report
        for record in (
            _db().session.scalars(select(Evidence).where(Evidence.id.in_(evidence_ids))) if evidence_ids else []
        )
        if isinstance((report := _stored_json(record.analysis_report)), dict)
    }
    reconstruction = _features().timeline.reconstruction.reconstruct(items, evidence_reports)
    payload["items"] = reconstruction["events"]
    payload["reconstruction"] = reconstruction
    payload["correlations"] = {
        "cases": sorted({item["case_number"] for item in items if item["case_number"]}),
        "evidence": sorted({item["evidence_number"] for item in items if item["evidence_number"]}),
        "groups": {
            name: sum(1 for item in items if item["group"] == name)
            for name in sorted({item["group"] for item in items})
        },
        "confirmed": reconstruction["summary"]["confirmed_events"],
        "correlated": reconstruction["summary"]["correlated_events"],
    }
    return jsonify(payload)


@api_v1_blueprint.get("/timeline/export")
def export_timeline():  # type: ignore[no-untyped-def]
    response = list_timeline()
    data = response.get_json()
    export_format = request.args.get("format", "csv").lower()
    if export_format == "json":
        return jsonify(data)
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "id",
            "case_number",
            "evidence_number",
            "occurred_at",
            "event_type",
            "group",
            "threat_level",
            "summary",
            "details",
        ],
    )
    writer.writeheader()
    for item in data["items"]:
        writer.writerow({key: item.get(key) for key in writer.fieldnames})
    return Response(
        output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=timeline.csv"}
    )


@api_v1_blueprint.post("/timeline/ai-summary")
def timeline_ai_summary():  # type: ignore[no-untyped-def]
    data = request.get_json(silent=True) or {}
    requested_case_id = str(data.get("case_id") or "").strip()
    if requested_case_id:
        try:
            parsed_case_id = _uuid(requested_case_id, "case_id")
        except ValueError as error:
            return _json_error(str(error), 400)
        if not _case_accessible(parsed_case_id):
            return _forbidden()
    context = _investigation_context(requested_case_id or None)
    if context.get("case_id") and not _case_accessible(_uuid(str(context["case_id"]), "case_id")):
        return _forbidden()
    completion = _ai_completion(
        "Summarize only the recorded investigation timeline. Separate confirmed facts from hypotheses, cite event "
        "IDs and evidence numbers, describe gaps, and do not invent attack stages, actors, malware, or ATT&CK mappings.",
        context,
    )
    completion["grounding"] = _ai_grounding(context)
    completion["instructions"] = {
        "facts": "Persisted timeline and evidence records",
        "hypotheses": "Must be explicitly labeled and require validation",
    }
    return jsonify(completion)


@api_v1_blueprint.post("/timeline")
def create_timeline_event():  # type: ignore[no-untyped-def]
    data = request.get_json(silent=True) or {}
    try:
        parsed_case_id = _uuid(str(data.get("case_id", "")), "case_id")
        if not _case_accessible(parsed_case_id):
            return _forbidden()
        summary = _normalize_text(data.get("summary"), limit=1024)
        if not summary:
            return _json_error("A timeline event summary is required.", 400)
        event_type = str(data.get("event_type") or "observation.manual")
        if event_type != "observation.manual":
            return _json_error("Manual timeline events must use observation.manual.", 400)
        event = _timeline_service().record_investigation_event(
            case_id=parsed_case_id,
            event_type=event_type,
            summary=summary,
            details=_normalize_text(data.get("details"), limit=8000),
        )
        _stamp_case_children(parsed_case_id)
        persisted_event = _db().session.get(TimelineEvent, event.id)
        _record_timeline_audit(persisted_event)
        _invalidate_dashboard_cache()
        return jsonify(_timeline_json(persisted_event)), 201
    except (ValueError, Exception) as error:
        return _json_error(str(error), 400)


@api_v1_blueprint.get("/reports")
def list_reports():  # type: ignore[no-untyped-def]
    statement = select(Report).order_by(Report.generated_at.desc())
    case_id = request.args.get("case_id")
    if case_id:
        try:
            statement = statement.where(Report.case_id == _uuid(case_id, "case_id"))
        except ValueError as error:
            return _json_error(str(error), 400)
    owned_ids = _owned_case_ids()
    if not owned_ids:
        return jsonify(_page([], total=0))
    statement = statement.where(Report.case_id.in_(owned_ids))
    items = [_report_json(report) for report in _db().session.scalars(statement)]
    query = _query_text()
    if query:
        items = [item for item in items if query in item["title"].lower() or query in item["report_type"].lower()]
    return jsonify(_page(items, total=len(items)))


@api_v1_blueprint.post("/reports")
def create_report():  # type: ignore[no-untyped-def]
    data = request.get_json(silent=True) or {}
    try:
        case_id = _uuid(str(data.get("case_id", "")), "case_id")
        if not _case_accessible(case_id):
            return _forbidden()
        session = _db().session
        case = session.get(Case, case_id)
        if case is None or case.deleted_at is not None:
            return _json_error("Case was not found.", 404)
        report_type = str(data.get("report_type", "investigation")).strip().lower() or "investigation"
        version = (
            session.scalar(
                select(func.max(Report.version)).where(Report.case_id == case_id, Report.report_type == report_type)
            )
            or 0
        ) + 1
        reports_dir = Path(current_app.config["REPORTS_FOLDER"]) / str(case_id)
        reports_dir.mkdir(parents=True, exist_ok=True)
        storage_path = str(
            (reports_dir / f"{report_type}-v{version}.json").relative_to(Path(current_app.config["REPORTS_FOLDER"]))
        )
        report = Report(
            case_id=case_id,
            owner_user_id=case.owner_user_id,
            created_by_user_id=_current_user_id(),
            report_type=report_type,
            version=version,
            title=str(data.get("title") or f"{case.case_number} {report_type.title()} Report v{version}"),
            storage_path=storage_path,
            status="generating",
        )
        session.add(report)
        session.commit()
        report_file = Path(current_app.config["REPORTS_FOLDER"]) / storage_path
        context = _investigation_context(str(case_id))
        ai_summary = {
            "available": False,
            "provider": {"provider": "pending", "message": "AI enrichment is queued."},
            "content": "AI enrichment is queued. The deterministic forensic report is ready now.",
        }
        document = _build_report_document(case_id, report_type, ai_summary)
        document["title"] = report.title
        document["report"] = _report_json(report)
        document["ai_summary"] = ai_summary
        report_file.write_text(json.dumps(document, indent=2, default=str), encoding="utf-8")
        _timeline_service().record_report_generation(
            case_id=case_id,
            report_type=report_type,
            version=version,
            storage_path=storage_path,
            event_type="report.generated",
        )
        _stamp_case_children(case_id)
        _invalidate_dashboard_cache()
        job = _start_report_enrichment_job(str(report.id), report_file, context)
        payload = _report_json(report)
        payload["generation_job"] = job
        _record_report_audit(report, "report.generation.requested")
        return jsonify(payload), 201
    except ValueError as error:
        return _json_error(str(error), 400)


@api_v1_blueprint.get("/reports/<report_id>")
def get_report(report_id: str):  # type: ignore[no-untyped-def]
    try:
        report = _db().session.get(Report, _uuid(report_id, "report_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if report is None:
        return _json_error("Report was not found.", 404)
    if not _case_accessible(report.case_id):
        return _forbidden()
    report_file = Path(current_app.config["REPORTS_FOLDER"]) / report.storage_path
    content = {}
    if report_file.exists():
        try:
            content = json.loads(report_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            content = {"warning": "Report content could not be parsed."}
    return jsonify({"metadata": _report_json(report), "content": content})


@api_v1_blueprint.patch("/reports/<report_id>")
def update_report(report_id: str):  # type: ignore[no-untyped-def]
    """Update investigator-authored review fields without mutating generated findings."""
    try:
        report = _db().session.get(Report, _uuid(report_id, "report_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if report is None:
        return _json_error("Report was not found.", 404)
    if not _case_accessible(report.case_id):
        return _forbidden()
    document_update = request.get_json(silent=True) or {}
    report_file = Path(current_app.config["REPORTS_FOLDER"]) / report.storage_path
    if not report_file.exists():
        return _json_error("Report file was not found.", 404)
    document = json.loads(report_file.read_text(encoding="utf-8"))
    action = "report.edited"
    if "title" in document_update:
        title = _normalize_text(document_update.get("title"), limit=512)
        if not title:
            return _json_error("Report title must not be empty.", 400)
        report.title = title
        document["title"] = title
    if "investigator_notes" in document_update:
        note = _normalize_text(document_update.get("investigator_notes"), limit=12000)
        document["investigator_notes"] = (
            [{"content": note, "authorship": "investigator", "source": f"user:{_current_user_id()}"}] if note else []
        )
    if "status" in document_update:
        status = str(document_update["status"]).strip().lower()
        if status not in {"draft", "in_review", "approved"}:
            return _json_error("Report status must be draft, in_review, or approved.", 400)
        report.status = status
        review = document.setdefault("review", {})
        review["status"] = status
        if status == "approved":
            review["approved_by"] = str(_current_user_id()) if _current_user_id() else _current_username()
            review["approved_at"] = utc_now().isoformat()
            action = "report.approved"
        else:
            review["approved_by"] = None
            review["approved_at"] = None
            action = "report.review_updated"
    report.updated_at = utc_now()
    temporary = report_file.with_suffix(f"{report_file.suffix}.tmp")
    temporary.write_text(json.dumps(document, indent=2, default=str), encoding="utf-8")
    temporary.replace(report_file)
    _db().session.commit()
    _record_report_audit(report, action)
    return jsonify({"metadata": _report_json(report), "content": document})


@api_v1_blueprint.post("/reports/<report_id>/analyze")
def analyze_report(report_id: str):  # type: ignore[no-untyped-def]
    try:
        report = _db().session.get(Report, _uuid(report_id, "report_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if report is None:
        return _json_error("Report was not found.", 404)
    if not _case_accessible(report.case_id):
        return _forbidden()
    report_file = Path(current_app.config["REPORTS_FOLDER"]) / report.storage_path
    if not report_file.exists():
        return _json_error("Report file was not found.", 404)
    try:
        document = json.loads(report_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return _json_error("Report content could not be parsed.", 400)
    context = _investigation_context(str(report.case_id))
    source = {"report": document, "context": context}
    analysis = _ai_completion(
        "Review this investigation report using only its source-linked records. Separate recorded facts from labeled "
        "hypotheses, identify traceability gaps, cite evidence IDs, preserve authorship, and do not create findings, "
        "recommendations, indicators, risk scores, or ATT&CK mappings.",
        source,
        max_tokens=1400,
    )
    if not analysis.get("available"):
        analysis["content"] = _local_report_analysis(document, context)
    _record_report_audit(report, "report.ai_analysis.requested")
    return jsonify({"report": _report_json(report), "analysis": analysis, "source": source})


@api_v1_blueprint.get("/reports/<report_id>/export")
def export_report(report_id: str):  # type: ignore[no-untyped-def]
    try:
        report = _db().session.get(Report, _uuid(report_id, "report_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if report is None:
        return _json_error("Report was not found.", 404)
    if not _case_accessible(report.case_id):
        return _forbidden()
    report_file = Path(current_app.config["REPORTS_FOLDER"]) / report.storage_path
    if not report_file.exists():
        return _json_error("Report file was not found.", 404)
    document = json.loads(report_file.read_text(encoding="utf-8"))
    export_format = request.args.get("format", "json").lower()
    if export_format not in {"json", "html", "md", "markdown", "csv", "xlsx", "excel", "docx", "pdf", "zip"}:
        return _json_error("Unsupported report export format.", 400)
    policy = _governance_policy()
    mapping = _governance_classifications()
    assignment = mapping.get(str(report.case_id))
    explicit = isinstance(assignment, dict) and assignment.get("level") in CLASSIFICATION_LEVELS
    classification = str(assignment["level"]) if explicit else str(policy.get("default_classification") or "internal")
    if policy.get("classification_required") is True and not explicit:
        _record_governance_audit(
            "governance.export.blocked",
            f"report:{report.id}",
            result="blocked",
            reason="Explicit investigation classification is required.",
        )
        return _json_error("Export requires an explicit investigation classification.", 409)
    allowed_by_level = policy.get("allowed_export_formats")
    allowed = allowed_by_level.get(classification, []) if isinstance(allowed_by_level, dict) else []
    if export_format not in allowed:
        _record_governance_audit(
            "governance.export.blocked",
            f"report:{report.id}",
            result="blocked",
            reason=f"classification:{classification} format:{export_format}",
        )
        return _json_error("Export format is not permitted for this investigation classification.", 403)
    export_reason = str(request.headers.get("X-Export-Reason") or "").strip()
    if policy.get("export_reason_required") is True and len(export_reason) < 10:
        return _json_error("X-Export-Reason with at least 10 characters is required.", 400)
    base_name = f"{report.report_type}-v{report.version}"
    _record_report_audit(
        report,
        "report.exported",
        reason=(
            f"format:{export_format} · version:{report.version} · classification:{classification}"
            f" · purpose:{export_reason[:500] or 'not_required'}"
        ),
    )
    if export_format == "html":
        return Response(
            _report_html(document),
            mimetype="text/html",
            headers={"Content-Disposition": f"attachment; filename={base_name}.html"},
        )
    if export_format in {"md", "markdown"}:
        return Response(
            _report_markdown(document),
            mimetype="text/markdown",
            headers={"Content-Disposition": f"attachment; filename={base_name}.md"},
        )
    if export_format == "csv":
        return Response(
            _report_csv(document),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={base_name}.csv"},
        )
    if export_format in {"xlsx", "excel"}:
        return Response(
            _zip_xlsx(document),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename={base_name}.xlsx"},
        )
    if export_format == "docx":
        return Response(
            _zip_docx(str(document["title"]), _report_markdown(document)),
            mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f"attachment; filename={base_name}.docx"},
        )
    if export_format == "pdf":
        return Response(
            _simple_pdf(_report_markdown(document)),
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={base_name}.pdf"},
        )
    if export_format == "zip":
        package = BytesIO()
        with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(f"{base_name}.json", json.dumps(document, indent=2, default=str))
            archive.writestr(f"{base_name}.md", _report_markdown(document))
            archive.writestr(f"{base_name}.html", _report_html(document))
            archive.writestr(
                "manifest.json",
                json.dumps(
                    {
                        "report_id": str(report.id),
                        "case_id": str(report.case_id),
                        "generated_at": _iso(report.generated_at),
                        "contents": [f"{base_name}.json", f"{base_name}.md", f"{base_name}.html"],
                    },
                    indent=2,
                ),
            )
        return Response(
            package.getvalue(),
            mimetype="application/zip",
            headers={"Content-Disposition": f"attachment; filename={base_name}.zip"},
        )
    return Response(
        json.dumps(document, indent=2, default=str),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={base_name}.json"},
    )


@api_v1_blueprint.get("/settings")
def get_settings():  # type: ignore[no-untyped-def]
    session = _db().session
    stored = {
        f"{setting.namespace}.{setting.key}": {
            "value": setting.value,
            "value_type": setting.value_type,
            "updated_at": _iso(setting.updated_at),
        }
        for setting in session.scalars(select(Setting))
        if not setting.namespace.startswith("secret.")
    }
    return jsonify(
        {
            "config": {
                "ai_enabled": bool(current_app.config["AI_ENABLED"]),
                "ai_provider": current_app.config["AI_PROVIDER"],
                "ai_model": current_app.config["AI_MODEL"],
                "ai_temperature": float(current_app.config.get("AI_TEMPERATURE") or 0.2),
                "ai_max_tokens": int(current_app.config.get("AI_MAX_TOKENS") or 1200),
                "ai_streaming": bool(current_app.config.get("AI_STREAMING", True)),
                "ollama_endpoint": current_app.config.get("OLLAMA_ENDPOINT"),
                "providers": _provider_status_payload(),
                "plugins_enabled": bool(current_app.config["PLUGINS_ENABLED"]),
                "security_headers_enabled": bool(current_app.config["SECURITY_HEADERS_ENABLED"]),
                "max_content_length": current_app.config["MAX_CONTENT_LENGTH"],
            },
            "settings": stored,
        }
    )


@api_v1_blueprint.patch("/settings")
def update_settings():  # type: ignore[no-untyped-def]
    data = request.get_json(silent=True) or {}
    namespace = str(data.get("namespace", "workspace")).strip() or "workspace"
    values = data.get("settings", {})
    if not isinstance(values, dict):
        return _json_error("settings must be an object.", 400)
    updated = {}
    for key, value in values.items():
        key_text = str(key).strip()
        if not key_text:
            return _json_error("Setting keys must not be empty.", 400)
        if namespace == "ai":
            try:
                _apply_ai_setting(key_text, value)
            except ValueError as error:
                return _json_error(str(error), 400)
        setting = _set_setting(namespace, key_text, json.dumps(value), "json")
        updated[f"{namespace}.{key_text}"] = {"value": setting.value, "value_type": setting.value_type}
    if updated:
        _record_account_audit(
            "admin.settings.updated",
            f"settings:{namespace}",
            reason=f"Updated keys: {', '.join(sorted(values))}",
        )
    return jsonify({"updated": updated})


def _apply_ai_setting(key: str, value: object) -> None:
    providers = {"ollama", "openai", "gemini", "perplexity"}
    if key == "provider":
        provider = str(value).strip().lower()
        if provider not in providers:
            raise ValueError("AI provider must be Ollama, OpenAI, Gemini, or Perplexity.")
        current_app.config["AI_PROVIDER"] = provider
    elif key == "model":
        model = str(value).strip()
        if not model:
            raise ValueError("AI model must not be empty.")
        current_app.config["AI_MODEL"] = model
        if str(current_app.config.get("AI_PROVIDER", "ollama")) == "ollama":
            current_app.config["OLLAMA_MODEL"] = model
    elif key == "temperature":
        temperature = float(value)
        if temperature < 0 or temperature > 2:
            raise ValueError("AI temperature must be between 0 and 2.")
        current_app.config["AI_TEMPERATURE"] = temperature
    elif key == "max_tokens":
        max_tokens = int(value)
        if max_tokens < 1 or max_tokens > 32000:
            raise ValueError("AI max tokens must be between 1 and 32000.")
        current_app.config["AI_MAX_TOKENS"] = max_tokens
    elif key == "streaming":
        current_app.config["AI_STREAMING"] = bool(value)
    elif key == "enabled":
        current_app.config["AI_ENABLED"] = bool(value)
    elif key == "ollama_endpoint":
        current_app.config["OLLAMA_ENDPOINT"] = _validated_ai_endpoint(value)
    else:
        return
    managed_config = hydrate_ai_config(current_app.config, _db().session)
    current_app.extensions["cyberinvestigator_ai_registry"] = build_ai_registry(managed_config)


@api_v1_blueprint.get("/health/live")
def health_live():  # type: ignore[no-untyped-def]
    return jsonify({"status": "ok", "service": "cyberinvestigator"})


@api_v1_blueprint.get("/health/ready")
def health_ready():  # type: ignore[no-untyped-def]
    try:
        _db().session.execute(select(1)).scalar_one()
        database = "ok"
    except Exception:
        current_app.logger.exception("Readiness database check failed.")
        database = "error"
    plugins = "ok" if current_app.extensions.get("cyberinvestigator_plugin_load_error") is not True else "degraded"
    ai = _provider_status()
    status = "ok" if database == "ok" else "error"
    return jsonify(
        {"status": status, "database": database, "plugins": plugins, "ai": ai}
    ), 200 if status == "ok" else 503


@api_v1_blueprint.get("/monitoring/metrics")
@require_role("admin")
def monitoring_metrics():  # type: ignore[no-untyped-def]
    session = _db().session
    telemetry = current_app.extensions["cyberinvestigator_telemetry"].snapshot()
    return jsonify(
        {
            "cases": session.scalar(
                select(func.count()).select_from(Case).where(Case.organization_id == _current_organization_id())
            ),
            "evidence": session.scalar(select(func.count()).select_from(Evidence)),
            "timeline_events": session.scalar(select(func.count()).select_from(TimelineEvent)),
            "reports": session.scalar(select(func.count()).select_from(Report)),
            "plugins_loaded": current_app.extensions.get("cyberinvestigator_plugin_loaded_count", 0),
            "rate_limit_requests": current_app.config.get("RATE_LIMIT_REQUESTS"),
            "telemetry": telemetry,
            "collected_at": _iso(utc_now()),
        }
    )


@api_v1_blueprint.get("/admin/observability")
@require_role("admin")
def observability_workspace():  # type: ignore[no-untyped-def]
    """Return measured, bounded telemetry and explicitly label unavailable sources."""
    session = _db().session
    registry = current_app.extensions["cyberinvestigator_telemetry"]
    readiness_response, readiness_status = health_ready()
    readiness = readiness_response.get_json()
    alerts = list(
        session.scalars(
            select(SecurityAlert)
            .where(SecurityAlert.status.in_(["open", "acknowledged"]))
            .order_by(SecurityAlert.created_at.desc())
            .limit(50)
        )
    )
    audit_events = list(session.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(50)))
    audit_writer = current_app.extensions.get("cyberinvestigator_audit_writer")
    audit_integrity = (
        audit_writer.verify_integrity()
        if audit_writer is not None and hasattr(audit_writer, "verify_integrity")
        else {"valid": None, "reason": "Audit writer unavailable."}
    )
    log_path = Path(current_app.config["LOGS_FOLDER"]) / "cyberinvestigator.log"
    log_events: list[dict[str, object]] = []
    if log_path.is_file():
        try:
            lines = _tail_file(log_path, lines=100)
        except OSError:  # pragma: no cover - helper already degrades safely.
            lines = []
        for line in reversed(lines):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                payload = {"timestamp": None, "level": "UNKNOWN", "message": line}
            log_events.append(
                {
                    "timestamp": payload.get("timestamp"),
                    "level": payload.get("level"),
                    "logger": payload.get("logger"),
                    "message": redact_text(payload.get("message", "")),
                    "request_id": payload.get("request_id"),
                    "trace_id": payload.get("trace_id"),
                }
            )
    telemetry = registry.snapshot()
    return jsonify(
        {
            "collected_at": _iso(utc_now()),
            "status": "operational" if readiness_status == 200 else "degraded",
            "critical_alerts": [_security_alert_json(item) for item in alerts if item.level in {"critical", "high"}],
            "health": readiness,
            "services": [
                {"name": "Database", "status": readiness.get("database"), "source": "readiness probe"},
                {"name": "Plugin runtime", "status": readiness.get("plugins"), "source": "plugin loader"},
                {
                    "name": "AI provider",
                    "status": "ok" if readiness.get("ai", {}).get("available") else "degraded",
                    "source": "provider registry",
                },
                {
                    "name": "Audit chain",
                    "status": "ok" if audit_integrity.get("valid") is True else "degraded",
                    "source": "hash-chain verification",
                },
            ],
            "telemetry": telemetry,
            "traces": registry.recent_traces(100),
            "recent_events": [_audit_log_json(item) for item in audit_events],
            "logs": {
                "available": log_path.is_file(),
                "events": log_events,
                "format": "structured_json",
            },
            "audit_integrity": audit_integrity,
            "sources": [
                {
                    "name": "Application request telemetry",
                    "status": "available",
                    "scope": "current_process",
                    "detail": "Bounded in-memory measurements; cleared when this process restarts.",
                },
                {
                    "name": "Application logs",
                    "status": "available" if log_path.is_file() else "unavailable",
                    "scope": "local_rotating_file",
                    "detail": "Secrets are redacted before persistence and presentation.",
                },
                {
                    "name": "Distributed trace exporter",
                    "status": "unavailable",
                    "scope": None,
                    "detail": "No external trace collector is configured.",
                },
                {
                    "name": "Infrastructure metrics collector",
                    "status": "unavailable",
                    "scope": None,
                    "detail": "No external infrastructure collector is configured.",
                },
            ],
        }
    )


def _storage_policy() -> dict[str, object]:
    configured = _setting_json("storage", "policy", {})
    document = configured if isinstance(configured, dict) else {}
    return {
        "evidence_retention_days": document.get("evidence_retention_days"),
        "backup_retention_days": int(document.get("backup_retention_days") or 30),
        "backup_schedule_enabled": bool(document.get("backup_schedule_enabled", False)),
        "backup_schedule": str(document.get("backup_schedule") or "manual"),
        "scheduler_status": "unavailable",
        "scheduler_detail": "No persistent backup scheduler is configured; manual verified backups remain available.",
    }


def _legal_holds() -> dict[str, dict[str, object]]:
    configured = _setting_json("storage", "legal_holds", {})
    return configured if isinstance(configured, dict) else {}


def _case_has_legal_hold(case_id: UUID) -> bool:
    hold = _legal_holds().get(str(case_id))
    return bool(isinstance(hold, dict) and hold.get("active") is True)


def _storage_notification(title: str, message: str, *, priority: str = "info") -> None:
    _db().session.add(
        Notification(
            title=title,
            message=message,
            category="storage",
            priority=priority,
            pinned=priority in {"high", "critical"},
        )
    )
    _db().session.commit()


def _record_storage_audit(action: str, affected_object: str, *, result: str, reason: str) -> None:
    _db().session.add(
        AuditLog(
            user_id=_current_user_id(),
            username=_current_username(),
            role=_current_user_role(),
            action=action,
            result=result,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            affected_object=affected_object,
            reason=reason,
        )
    )
    _db().session.commit()


@api_v1_blueprint.get("/admin/storage")
@require_role("admin")
def storage_workspace():  # type: ignore[no-untyped-def]
    """Return measured local provider state and persisted continuity records."""
    payload = _storage_manager().workspace()
    holds = _legal_holds()
    integrity = _setting_json(
        "storage",
        "last_integrity_verification",
        {"status": "not_checked", "detail": "Run an integrity verification to compare custody bytes with records."},
    )
    restores = _setting_json("storage", "restore_plans", [])
    alerts = list(
        _db().session.scalars(
            select(SecurityAlert)
            .where(SecurityAlert.category == "storage", SecurityAlert.status.in_(["open", "acknowledged"]))
            .order_by(SecurityAlert.created_at.desc())
            .limit(50)
        )
    )
    payload.update(
        {
            "collected_at": _iso(utc_now()),
            "policy": _storage_policy(),
            "legal_holds": list(holds.values()),
            "active_legal_holds": sum(1 for item in holds.values() if item.get("active") is True),
            "integrity": integrity,
            "alerts": [_security_alert_json(item) for item in alerts],
            "recent_restores": restores[:20] if isinstance(restores, list) else [],
            "recovery": {
                "automatic_restore": False,
                "mode": "verified_offline_restore",
                "rpo": None,
                "rto": None,
                "detail": "Recovery objectives are not configured and are not inferred.",
            },
        }
    )
    return jsonify(payload)


@api_v1_blueprint.patch("/admin/storage/policy")
@require_role("admin")
def update_storage_policy():  # type: ignore[no-untyped-def]
    body = request.get_json(silent=True) or {}
    evidence_days = body.get("evidence_retention_days")
    if evidence_days not in (None, ""):
        evidence_days = int(evidence_days)
        if evidence_days < 1:
            return _json_error("Evidence retention must be at least one day.", 400)
    else:
        evidence_days = None
    backup_days = int(body.get("backup_retention_days", 30))
    if backup_days < 1:
        return _json_error("Backup retention must be at least one day.", 400)
    schedule = str(body.get("backup_schedule") or "manual")
    if schedule not in {"manual", "daily", "weekly"}:
        return _json_error("Backup schedule must be manual, daily, or weekly.", 400)
    policy = {
        "evidence_retention_days": evidence_days,
        "backup_retention_days": backup_days,
        "backup_schedule_enabled": bool(body.get("backup_schedule_enabled", False)),
        "backup_schedule": schedule,
    }
    _set_setting("storage", "policy", json.dumps(policy), "json")
    _record_account_audit("storage.policy.updated", "storage:policy", reason=f"schedule:{schedule}")
    return jsonify(_storage_policy())


@api_v1_blueprint.patch("/admin/storage/legal-holds/<case_id>")
@require_role("admin")
def update_legal_hold(case_id: str):  # type: ignore[no-untyped-def]
    try:
        parsed_case_id = _uuid(case_id, "case_id")
    except ValueError as error:
        return _json_error(str(error), 400)
    case = _db().session.get(Case, parsed_case_id)
    if case is None:
        return _json_error("Investigation was not found.", 404)
    body = request.get_json(silent=True) or {}
    active = bool(body.get("active"))
    reason = str(body.get("reason") or "").strip()
    if active and not reason:
        return _json_error("A legal hold reason is required.", 400)
    holds = _legal_holds()
    hold = {
        "case_id": str(case.id),
        "case_number": case.case_number,
        "case_title": case.title,
        "active": active,
        "reason": reason,
        "updated_at": _iso(utc_now()),
        "updated_by": _current_username(),
    }
    holds[str(case.id)] = hold
    _set_setting("storage", "legal_holds", json.dumps(holds), "json")
    action = "storage.legal_hold.applied" if active else "storage.legal_hold.released"
    _record_account_audit(action, f"case:{case.id}", reason=reason or "Legal hold released.")
    _storage_notification(
        f"Legal hold {'applied' if active else 'released'}",
        f"{case.case_number}: {reason or 'Hold released by an administrator.'}",
        priority="high" if active else "info",
    )
    return jsonify(hold)


@api_v1_blueprint.post("/admin/storage/backups")
@require_role("admin")
def create_storage_backup():  # type: ignore[no-untyped-def]
    try:
        backup = _storage_manager().create_backup()
    except StorageOperationError as error:
        _record_storage_audit("storage.backup.failed", "storage:backup", result="failure", reason=str(error))
        _storage_notification("Backup failed", str(error), priority="high")
        return _json_error(str(error), 503)
    _record_storage_audit(
        "storage.backup.created",
        f"backup:{backup['backup_id']}",
        result="success",
        reason=f"files:{backup['file_count']} bytes:{backup['size_bytes']}",
    )
    _storage_notification(
        "Verified backup created",
        f"Backup {backup['backup_id']} passed manifest verification.",
    )
    return jsonify(backup), 201


@api_v1_blueprint.post("/admin/storage/backups/<backup_id>/verify")
@require_role("admin")
def verify_storage_backup(backup_id: str):  # type: ignore[no-untyped-def]
    try:
        result = _storage_manager().verify_backup(backup_id)
    except StorageOperationError as error:
        return _json_error(str(error), 404)
    _record_storage_audit(
        "storage.backup.verified" if result["valid"] else "storage.backup.verification_failed",
        f"backup:{backup_id}",
        result="success" if result["valid"] else "failure",
        reason=f"files_checked:{result['files_checked']}",
    )
    if result["valid"] is not True:
        _storage_notification("Backup verification failed", f"Backup {backup_id} requires review.", priority="high")
    return jsonify(result), 200 if result["valid"] is True else 409


@api_v1_blueprint.post("/admin/storage/restore-plans")
@require_role("admin")
def create_restore_plan():  # type: ignore[no-untyped-def]
    backup_id = str((request.get_json(silent=True) or {}).get("backup_id") or "")
    try:
        plan = _storage_manager().restore_plan(backup_id)
    except StorageOperationError as error:
        _record_storage_audit(
            "storage.restore_plan.rejected",
            f"backup:{backup_id}",
            result="blocked",
            reason=str(error),
        )
        return _json_error(str(error), 409)
    history = _setting_json("storage", "restore_plans", [])
    records = history if isinstance(history, list) else []
    plan["created_at"] = _iso(utc_now())
    plan["created_by"] = _current_username()
    records.insert(0, plan)
    _set_setting("storage", "restore_plans", json.dumps(records[:100]), "json")
    _record_storage_audit(
        "storage.restore_plan.created",
        f"backup:{backup_id}",
        result="success",
        reason="Verified offline restore plan; no restore executed.",
    )
    return jsonify(plan), 201


@api_v1_blueprint.post("/admin/storage/integrity/verify")
@require_role("admin")
def verify_evidence_integrity():  # type: ignore[no-untyped-def]
    records = list(_db().session.scalars(select(Evidence).order_by(Evidence.created_at)))
    failures: list[dict[str, str]] = []
    checked = 0
    for evidence in records:
        try:
            path = _features().evidence.resolve_path(evidence.storage_path)
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
            if digest.hexdigest() != evidence.sha256 or path.stat().st_size != evidence.size_bytes:
                failures.append({"evidence_id": str(evidence.id), "reason": "integrity_mismatch"})
                continue
            checked += 1
        except (OSError, EvidenceManagementError):
            failures.append({"evidence_id": str(evidence.id), "reason": "custody_file_unavailable"})
    result = {
        "status": "verified" if not failures else "failed",
        "valid": not failures,
        "records_checked": checked,
        "records_total": len(records),
        "failures": failures,
        "verified_at": _iso(utc_now()),
    }
    _set_setting("storage", "last_integrity_verification", json.dumps(result), "json")
    _record_storage_audit(
        "storage.evidence_integrity.verified" if not failures else "storage.evidence_integrity.failed",
        "storage:evidence",
        result="success" if not failures else "failure",
        reason=f"checked:{checked} failures:{len(failures)}",
    )
    if failures:
        _storage_notification(
            "Evidence integrity verification failed",
            f"{len(failures)} custody records require immediate review.",
            priority="critical",
        )
    return jsonify(result), 200 if not failures else 409


def _deployment_workspace_payload() -> dict[str, object]:
    return _deployment_inspector().workspace(
        environment=str(current_app.config.get("ENVIRONMENT") or "development"),
        last_verification=_setting_json("deployment", "last_verification", None),
        release_catalog=_setting_json("deployment", "release_catalog", []),
    )


def _record_deployment_audit(action: str, affected_object: str, *, result: str, reason: str) -> None:
    _db().session.add(
        AuditLog(
            user_id=_current_user_id(),
            username=_current_username(),
            role=_current_user_role(),
            action=action,
            result=result,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            affected_object=affected_object,
            reason=reason,
        )
    )
    _db().session.commit()


@api_v1_blueprint.get("/admin/deployments")
@require_role("admin")
def deployment_workspace():  # type: ignore[no-untyped-def]
    """Expose runtime and repository release state without inventing CI history."""
    payload = _deployment_workspace_payload()
    payload["rollback_plans"] = _setting_json("deployment", "rollback_plans", [])
    payload["release_approvals"] = _setting_json("deployment", "release_approvals", [])
    return jsonify(payload)


@api_v1_blueprint.post("/admin/deployments/release-approvals")
@require_role("admin")
def record_release_approval():  # type: ignore[no-untyped-def]
    """Record an administrator's release decision; deployment remains externally gated."""
    body = request.get_json(silent=True) or {}
    decision = str(body.get("decision") or "").strip().lower()
    reason = str(body.get("reason") or "").strip()
    release = _deployment_inspector().current_release(str(current_app.config.get("ENVIRONMENT") or "development"))
    if decision not in {"approved", "rejected"}:
        return _json_error("decision must be approved or rejected.", 400)
    if len(reason) < 10:
        return _json_error("A release decision reason of at least 10 characters is required.", 400)
    if not release.get("git_sha"):
        return _json_error("Release approval requires immutable build revision metadata.", 409)
    record = {
        "decision": decision,
        "reason": reason[:1000],
        "release_version": release["version"],
        "git_sha": release["git_sha"],
        "image_digest": release.get("digest"),
        "environment": release["environment"],
        "recorded_at": _iso(utc_now()),
        "recorded_by": _current_username(),
        "deployment_executed": False,
    }
    history = _setting_json("deployment", "release_approvals", [])
    records = history if isinstance(history, list) else []
    records.insert(0, record)
    _set_setting("deployment", "release_approvals", json.dumps(records[:200]), "json")
    _record_deployment_audit(
        f"deployment.release.{decision}",
        f"release:{release['version']}@{release['git_sha']}",
        result="success",
        reason=reason[:1000],
    )
    return jsonify(record), 201


@api_v1_blueprint.get("/admin/quality")
@require_role("admin")
def quality_workspace():  # type: ignore[no-untyped-def]
    """Return only quality evidence generated by supported test tools."""
    return jsonify(_quality_inspector().workspace())


@api_v1_blueprint.get("/admin/performance")
@require_role("admin")
def performance_workspace():  # type: ignore[no-untyped-def]
    """Return current-process capacity evidence and explicit external gaps."""
    payload = _performance_inspector().snapshot(
        database=_db(),
        telemetry=current_app.extensions["cyberinvestigator_telemetry"],
        cache=current_app.extensions["cyberinvestigator_cache"],
        dispatcher=current_app.extensions["cyberinvestigator_job_dispatcher"],
    )
    payload["capacity_plan"] = _setting_json("performance", "capacity_plan", None)
    return jsonify(payload)


@api_v1_blueprint.patch("/admin/performance/capacity-plan")
@require_role("admin")
def update_capacity_plan():  # type: ignore[no-untyped-def]
    body = request.get_json(silent=True) or {}
    reason = str(body.get("reason") or "").strip()
    if len(reason) < 10:
        return _json_error("A capacity-planning reason of at least 10 characters is required.", 400)
    plan: dict[str, object] = {
        "updated_at": _iso(utc_now()),
        "updated_by": _current_username(),
        "reason": reason[:1000],
    }
    for field in ("target_p95_ms", "maximum_queue_depth", "minimum_free_storage_percent"):
        value = body.get(field)
        if value in (None, ""):
            plan[field] = None
            continue
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return _json_error(f"{field} must be numeric.", 400)
        if parsed <= 0:
            return _json_error(f"{field} must be greater than zero.", 400)
        plan[field] = parsed
    _set_setting("performance", "capacity_plan", json.dumps(plan), "json")
    _record_deployment_audit(
        "performance.capacity_plan.updated",
        "performance:capacity_plan",
        result="success",
        reason=reason[:1000],
    )
    return jsonify(plan)


@api_v1_blueprint.post("/admin/performance/cache/invalidate")
@require_role("admin")
def invalidate_performance_cache():  # type: ignore[no-untyped-def]
    reason = str((request.get_json(silent=True) or {}).get("reason") or "").strip()
    if len(reason) < 10:
        return _json_error("A cache invalidation reason of at least 10 characters is required.", 400)
    removed = current_app.extensions["cyberinvestigator_cache"].invalidate()
    _record_deployment_audit(
        "performance.cache.invalidated",
        "cache:current_process",
        result="success",
        reason=f"{reason[:900]} entries:{removed}",
    )
    return jsonify({"status": "completed", "entries_removed": removed, "scope": "current_process"})


def _governance_policy() -> dict[str, object]:
    policy, _, error = decoded_setting(_db().session, "governance", "policy", DEFAULT_GOVERNANCE_POLICY)
    return policy if error is None and isinstance(policy, dict) else DEFAULT_GOVERNANCE_POLICY


def _governance_classifications() -> dict[str, dict[str, object]]:
    mapping, _, error = decoded_setting(_db().session, "governance", "classifications", {})
    return mapping if error is None and isinstance(mapping, dict) else {}


def _record_governance_audit(action: str, affected_object: str, *, result: str, reason: str) -> None:
    _record_deployment_audit(action, affected_object, result=result, reason=reason)


def _organization_membership(organization_id: UUID, user_id: UUID | None = None):
    return _db().session.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.user_id == (user_id or _current_user_id()),
            OrganizationMembership.status == "active",
        )
    )


def _organization_quota(resource: str) -> OrganizationQuota | None:
    return _db().session.scalar(
        select(OrganizationQuota).where(
            OrganizationQuota.organization_id == _current_organization_id(),
            OrganizationQuota.resource == resource,
            OrganizationQuota.enabled.is_(True),
        )
    )


def _organization_settings() -> dict[str, object]:
    records = list(
        _db().session.scalars(
            select(OrganizationSetting).where(
                OrganizationSetting.organization_id == _current_organization_id(),
                OrganizationSetting.sensitive.is_(False),
            )
        )
    )
    result: dict[str, object] = {}
    for item in records:
        try:
            result[item.key] = json.loads(item.value) if item.value_type == "json" else item.value
        except json.JSONDecodeError:
            result[item.key] = None
    return result


def _organization_audit(action: str, affected_object: str, *, result: str = "success", reason: str) -> None:
    _record_deployment_audit(action, affected_object, result=result, reason=reason)


@api_v1_blueprint.get("/organizations")
@require_role("user")
def list_organizations():  # type: ignore[no-untyped-def]
    user_id = _current_user_id()
    if user_id is None:
        organization = _db().session.get(Organization, _current_organization_id())
        return jsonify(
            {
                "items": [
                    {
                        "id": str(organization.id),
                        "name": organization.name,
                        "slug": organization.slug,
                        "status": organization.status,
                        "organization_role": "owner" if _is_admin() else "member",
                        "subscription_status": organization.subscription_status,
                    }
                ]
                if organization is not None
                else [],
                "active_organization_id": str(_current_organization_id()),
            }
        )
    memberships = list(
        _db().session.scalars(
            select(OrganizationMembership)
            .where(
                OrganizationMembership.user_id == user_id,
                OrganizationMembership.status == "active",
            )
            .order_by(OrganizationMembership.created_at)
        )
    )
    organizations = {
        item.id: item
        for item in _db().session.scalars(
            select(Organization).where(Organization.id.in_([membership.organization_id for membership in memberships]))
        )
    }
    return jsonify(
        {
            "active_organization_id": str(_current_organization_id()),
            "items": [
                {
                    "id": str(organization.id),
                    "name": organization.name,
                    "slug": organization.slug,
                    "status": organization.status,
                    "organization_role": membership.organization_role,
                    "subscription_status": organization.subscription_status,
                }
                for membership in memberships
                if (organization := organizations.get(membership.organization_id)) is not None
            ],
        }
    )


@api_v1_blueprint.post("/organizations")
@require_role("admin")
def create_organization():  # type: ignore[no-untyped-def]
    body = request.get_json(silent=True) or {}
    name = str(body.get("name") or "").strip()
    slug = str(body.get("slug") or "").strip().lower()
    reason = str(body.get("reason") or "").strip()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,63}", slug):
        return _json_error("Organization slug must contain 3-64 lowercase letters, numbers, or hyphens.", 400)
    if len(name) < 2 or len(reason) < 10:
        return _json_error("Organization name and a reason of at least 10 characters are required.", 400)
    if _db().session.scalar(select(Organization).where(Organization.slug == slug)):
        return _json_error("Organization slug is already in use.", 409)
    organization = Organization(name=name[:255], slug=slug, status="active", subscription_status=None)
    _db().session.add(organization)
    _db().session.flush()
    _db().session.add(
        OrganizationMembership(
            organization_id=organization.id,
            user_id=_current_user_id(),
            organization_role="owner",
            status="active",
        )
    )
    _db().session.commit()
    _organization_audit(
        "organization.created",
        f"organization:{organization.id}",
        reason=reason[:1000],
    )
    return (
        jsonify(
            {
                "id": str(organization.id),
                "name": organization.name,
                "slug": organization.slug,
                "status": organization.status,
                "subscription_status": None,
            }
        ),
        201,
    )


@api_v1_blueprint.post("/organizations/<organization_id>/switch")
@require_role("user")
def switch_organization(organization_id: str):  # type: ignore[no-untyped-def]
    try:
        parsed = _uuid(organization_id, "organization_id")
    except ValueError as error:
        return _json_error(str(error), 400)
    membership = _organization_membership(parsed)
    organization = _db().session.get(Organization, parsed)
    if membership is None or organization is None or organization.status != "active":
        _organization_audit(
            "organization.switch.blocked",
            f"organization:{parsed}",
            result="blocked",
            reason="Active membership is required.",
        )
        return _json_error("Active organization membership is required.", 403)
    previous = _current_organization_id()
    flask_session["organization_id"] = str(parsed)
    _organization_audit(
        "organization.switched",
        f"organization:{parsed}",
        reason=f"from:{previous}",
    )
    _runtime_cache().invalidate()
    return jsonify({"active_organization_id": str(parsed), "name": organization.name})


@api_v1_blueprint.get("/organizations/current")
@require_role("user")
def organization_workspace():  # type: ignore[no-untyped-def]
    organization_id = _current_organization_id()
    organization = _db().session.get(Organization, organization_id)
    memberships = list(
        _db().session.scalars(
            select(OrganizationMembership)
            .where(OrganizationMembership.organization_id == organization_id)
            .order_by(OrganizationMembership.created_at)
        )
    )
    user_ids = [item.user_id for item in memberships]
    users = (
        {item.id: item for item in _db().session.scalars(select(User).where(User.id.in_(user_ids)))} if user_ids else {}
    )
    case_ids = list(_db().session.scalars(select(Case.id).where(Case.organization_id == organization_id)))
    invitations = list(
        _db().session.scalars(
            select(OrganizationInvitation)
            .where(OrganizationInvitation.organization_id == organization_id)
            .order_by(OrganizationInvitation.created_at.desc())
            .limit(100)
        )
    )
    quotas = list(
        _db().session.scalars(select(OrganizationQuota).where(OrganizationQuota.organization_id == organization_id))
    )
    return jsonify(
        {
            "collected_at": _iso(utc_now()),
            "organization_overview": {
                "id": str(organization.id),
                "name": organization.name,
                "slug": organization.slug,
                "status": organization.status,
                "subscription_status": organization.subscription_status,
                "subscription_detail": "No subscription provider is connected."
                if organization.subscription_status is None
                else None,
            },
            "usage": {
                "investigations": len(case_ids),
                "evidence": (
                    _db().session.scalar(
                        select(func.count()).select_from(Evidence).where(Evidence.case_id.in_(case_ids))
                    )
                    if case_ids
                    else 0
                ),
                "reports": (
                    _db().session.scalar(select(func.count()).select_from(Report).where(Report.case_id.in_(case_ids)))
                    if case_ids
                    else 0
                ),
                "members": len(memberships),
                "source": "current persisted organization records",
            },
            "quotas": [
                {
                    "resource": item.resource,
                    "limit": item.limit_value,
                    "enabled": item.enabled,
                    "usage": (
                        len(case_ids)
                        if item.resource == "investigations"
                        else len(memberships)
                        if item.resource == "members"
                        else None
                    ),
                }
                for item in quotas
            ],
            "settings": _organization_settings(),
            "members": [
                {
                    "user_id": str(item.user_id),
                    "username": users[item.user_id].username if item.user_id in users else None,
                    "email": users[item.user_id].email if item.user_id in users else None,
                    "organization_role": item.organization_role,
                    "status": item.status,
                }
                for item in memberships
            ],
            "invitations": [
                {
                    "id": str(item.id),
                    "email": item.email,
                    "organization_role": item.organization_role,
                    "status": item.status,
                    "expires_at": _iso(item.expires_at),
                    "delivery_status": "unavailable",
                }
                for item in invitations
            ],
        }
    )


@api_v1_blueprint.put("/organizations/current/settings")
@require_role("admin")
def update_organization_settings():  # type: ignore[no-untyped-def]
    body = request.get_json(silent=True) or {}
    reason = str(body.get("reason") or "").strip()
    settings = body.get("settings")
    if len(reason) < 10 or not isinstance(settings, dict):
        return _json_error("Settings and a reason of at least 10 characters are required.", 400)
    allowed = {"timezone", "locale", "default_case_severity"}
    unknown = set(settings) - allowed
    if unknown:
        return _json_error(f"Unsupported organization settings: {', '.join(sorted(unknown))}.", 400)
    if "default_case_severity" in settings and settings["default_case_severity"] not in {
        "critical",
        "high",
        "medium",
        "low",
        "informational",
    }:
        return _json_error("default_case_severity is invalid.", 400)
    for key, value in settings.items():
        record = _db().session.scalar(
            select(OrganizationSetting).where(
                OrganizationSetting.organization_id == _current_organization_id(),
                OrganizationSetting.key == key,
            )
        )
        if record is None:
            _db().session.add(
                OrganizationSetting(
                    organization_id=_current_organization_id(),
                    key=key,
                    value=json.dumps(value),
                    value_type="json",
                    sensitive=False,
                )
            )
        else:
            record.value = json.dumps(value)
            record.value_type = "json"
    _db().session.commit()
    _organization_audit(
        "organization.settings.updated",
        f"organization:{_current_organization_id()}:settings",
        reason=reason[:1000],
    )
    return jsonify({"settings": _organization_settings()})


@api_v1_blueprint.post("/organizations/current/invitations")
@require_role("admin")
def create_organization_invitation():  # type: ignore[no-untyped-def]
    body = request.get_json(silent=True) or {}
    email = str(body.get("email") or "").strip().lower()
    organization_role = str(body.get("organization_role") or "member").lower()
    reason = str(body.get("reason") or "").strip()
    if "@" not in email or organization_role not in {"member", "admin"} or len(reason) < 10:
        return _json_error("Valid email, organization role, and reason are required.", 400)
    quota = _organization_quota("members")
    if quota is not None:
        active_members = (
            _db().session.scalar(
                select(func.count())
                .select_from(OrganizationMembership)
                .where(
                    OrganizationMembership.organization_id == _current_organization_id(),
                    OrganizationMembership.status == "active",
                )
            )
            or 0
        )
        pending_invitations = (
            _db().session.scalar(
                select(func.count())
                .select_from(OrganizationInvitation)
                .where(
                    OrganizationInvitation.organization_id == _current_organization_id(),
                    OrganizationInvitation.status == "pending",
                )
            )
            or 0
        )
        if active_members + pending_invitations >= quota.limit_value:
            _organization_audit(
                "organization.quota.blocked",
                f"organization:{_current_organization_id()}:quota:members",
                result="blocked",
                reason=f"limit:{quota.limit_value} usage:{active_members + pending_invitations}",
            )
            return _json_error("Organization member quota has been reached.", 409)
    token = secrets.token_urlsafe(32)
    invitation = OrganizationInvitation(
        organization_id=_current_organization_id(),
        email=email,
        organization_role=organization_role,
        status="pending",
        invited_by_user_id=_current_user_id(),
        token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
        expires_at=utc_now() + timedelta(days=7),
    )
    _db().session.add(invitation)
    _db().session.commit()
    _organization_audit(
        "organization.invitation.created",
        f"organization_invitation:{invitation.id}",
        reason=reason[:1000],
    )
    return (
        jsonify(
            {
                "id": str(invitation.id),
                "email": invitation.email,
                "organization_role": invitation.organization_role,
                "status": invitation.status,
                "expires_at": _iso(invitation.expires_at),
                "delivery_status": "unavailable",
                "delivery_detail": "No email invitation delivery provider is connected.",
            }
        ),
        201,
    )


@api_v1_blueprint.put("/organizations/current/quotas/<resource>")
@require_role("admin")
def update_organization_quota(resource: str):  # type: ignore[no-untyped-def]
    if resource not in {"investigations", "members", "storage_bytes", "ai_requests"}:
        return _json_error("Unsupported quota resource.", 400)
    body = request.get_json(silent=True) or {}
    reason = str(body.get("reason") or "").strip()
    try:
        limit_value = int(body.get("limit"))
    except (TypeError, ValueError):
        return _json_error("Quota limit must be an integer.", 400)
    if limit_value < 1 or len(reason) < 10:
        return _json_error("Positive quota limit and reason are required.", 400)
    quota = _db().session.scalar(
        select(OrganizationQuota).where(
            OrganizationQuota.organization_id == _current_organization_id(),
            OrganizationQuota.resource == resource,
        )
    )
    if quota is None:
        quota = OrganizationQuota(
            organization_id=_current_organization_id(),
            resource=resource,
            limit_value=limit_value,
            enabled=bool(body.get("enabled", True)),
        )
        _db().session.add(quota)
    else:
        quota.limit_value = limit_value
        quota.enabled = bool(body.get("enabled", True))
    _db().session.commit()
    _organization_audit(
        "organization.quota.updated",
        f"organization:{_current_organization_id()}:quota:{resource}",
        reason=reason[:1000],
    )
    return jsonify({"resource": resource, "limit": quota.limit_value, "enabled": quota.enabled})


@api_v1_blueprint.get("/admin/governance")
@require_role("admin")
def governance_workspace():  # type: ignore[no-untyped-def]
    """Aggregate only persisted governance, custody, and audit evidence."""
    storage = storage_workspace().get_json()
    return jsonify(
        _governance_inspector().snapshot(
            session=_db().session,
            storage=storage,
        )
    )


@api_v1_blueprint.get("/admin/governance/report")
@require_role("admin")
def export_governance_report():  # type: ignore[no-untyped-def]
    """Export a point-in-time governance evidence report without certification claims."""
    export_format = str(request.args.get("format") or "json").lower()
    if export_format not in {"json", "csv"}:
        return _json_error("Governance reports support json or csv.", 400)
    payload = _governance_inspector().snapshot(
        session=_db().session,
        storage=storage_workspace().get_json(),
    )
    _record_governance_audit(
        "governance.report.exported",
        "governance:point_in_time_report",
        result="success",
        reason=f"format:{export_format} collected_at:{payload['collected_at']}",
    )
    if export_format == "json":
        response = jsonify(payload)
        response.headers["Content-Disposition"] = "attachment; filename=governance-report.json"
        return response
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["metric", "value", "collected_at"])
    for key, value in payload["metrics"].items():
        writer.writerow([key, value, payload["collected_at"]])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=governance-report.csv"},
    )


@api_v1_blueprint.put("/admin/governance/policy")
@require_role("admin")
def update_governance_policy():  # type: ignore[no-untyped-def]
    body = request.get_json(silent=True) or {}
    reason = str(body.pop("reason", "") or "").strip()
    if len(reason) < 10:
        return _json_error("A policy change reason of at least 10 characters is required.", 400)
    default_level = str(body.get("default_classification") or "internal").lower()
    if default_level not in CLASSIFICATION_LEVELS:
        return _json_error("default_classification is invalid.", 400)
    retention_input = body.get("retention_days")
    retention = retention_input if isinstance(retention_input, dict) else {}
    formats_input = body.get("allowed_export_formats")
    formats = formats_input if isinstance(formats_input, dict) else {}
    allowed_formats = {"json", "html", "md", "markdown", "csv", "xlsx", "excel", "docx", "pdf", "zip"}
    policy = {
        "version": int(_governance_policy().get("version") or 0) + 1,
        "classification_required": bool(body.get("classification_required", False)),
        "default_classification": default_level,
        "retention_days": {},
        "allowed_export_formats": {},
        "export_reason_required": bool(body.get("export_reason_required", False)),
        "disposition_approval_required": bool(body.get("disposition_approval_required", True)),
        "updated_at": _iso(utc_now()),
        "updated_by": _current_username(),
    }
    for level in CLASSIFICATION_LEVELS:
        days = retention.get(level)
        if days in (None, ""):
            policy["retention_days"][level] = None
        elif not isinstance(days, int) or days < 1:
            return _json_error(f"retention_days.{level} must be a positive integer or null.", 400)
        else:
            policy["retention_days"][level] = days
        selected = formats.get(level, DEFAULT_GOVERNANCE_POLICY["allowed_export_formats"][level])
        if not isinstance(selected, list) or not selected or any(str(item) not in allowed_formats for item in selected):
            return _json_error(f"allowed_export_formats.{level} contains an unsupported format.", 400)
        policy["allowed_export_formats"][level] = sorted({str(item) for item in selected})
    _set_setting("governance", "policy", json.dumps(policy), "json")
    _record_governance_audit(
        "governance.policy.updated",
        f"governance:policy:v{policy['version']}",
        result="success",
        reason=reason[:1000],
    )
    _invalidate_dashboard_cache()
    return jsonify(policy)


@api_v1_blueprint.put("/admin/governance/classifications/<case_id>")
@require_role("admin")
def classify_investigation(case_id: str):  # type: ignore[no-untyped-def]
    try:
        parsed = _uuid(case_id, "case_id")
    except ValueError as error:
        return _json_error(str(error), 400)
    case = _db().session.get(Case, parsed)
    if case is None or case.deleted_at is not None:
        return _json_error("Investigation was not found.", 404)
    body = request.get_json(silent=True) or {}
    level = str(body.get("level") or "").lower()
    reason = str(body.get("reason") or "").strip()
    if level not in CLASSIFICATION_LEVELS:
        return _json_error("Classification level is invalid.", 400)
    if len(reason) < 10:
        return _json_error("A classification reason of at least 10 characters is required.", 400)
    mapping = _governance_classifications()
    assignment = {
        "level": level,
        "reason": reason[:1000],
        "updated_at": _iso(utc_now()),
        "updated_by": _current_username(),
    }
    mapping[str(case.id)] = assignment
    _set_setting("governance", "classifications", json.dumps(mapping), "json")
    _record_governance_audit(
        "governance.classification.updated",
        f"case:{case.id}",
        result="success",
        reason=f"level:{level} · {reason[:900]}",
    )
    _invalidate_dashboard_cache()
    return jsonify({"case_id": str(case.id), **assignment})


@api_v1_blueprint.post("/admin/governance/privacy-requests")
@require_role("admin")
def create_privacy_request():  # type: ignore[no-untyped-def]
    body = request.get_json(silent=True) or {}
    request_type = str(body.get("request_type") or "").lower()
    subject_reference = str(body.get("subject_reference") or "").strip()
    reason = str(body.get("reason") or "").strip()
    if request_type not in {"access", "correction", "restriction", "deletion_review"}:
        return _json_error("Privacy request type is invalid.", 400)
    if not subject_reference or len(reason) < 10:
        return _json_error("Subject reference and a reason of at least 10 characters are required.", 400)
    records, _, _ = decoded_setting(_db().session, "governance", "privacy_requests", [])
    history = records if isinstance(records, list) else []
    record = {
        "id": str(uuid4()),
        "request_type": request_type,
        "subject_reference": subject_reference[:255],
        "reason": reason[:1000],
        "status": "review_required",
        "created_at": _iso(utc_now()),
        "created_by": _current_username(),
        "automated_action_taken": False,
    }
    history.insert(0, record)
    _set_setting("governance", "privacy_requests", json.dumps(history[:500]), "json")
    _record_governance_audit(
        "privacy.request.created",
        f"privacy_request:{record['id']}",
        result="success",
        reason=f"type:{request_type}",
    )
    return jsonify(record), 201


@api_v1_blueprint.post("/admin/governance/disposition-reviews")
@require_role("admin")
def create_disposition_review():  # type: ignore[no-untyped-def]
    body = request.get_json(silent=True) or {}
    case_id = str(body.get("case_id") or "")
    reason = str(body.get("reason") or "").strip()
    try:
        parsed = _uuid(case_id, "case_id")
    except ValueError as error:
        return _json_error(str(error), 400)
    case = _db().session.get(Case, parsed)
    if case is None:
        return _json_error("Investigation was not found.", 404)
    if _case_has_legal_hold(parsed):
        _record_governance_audit(
            "governance.disposition.blocked",
            f"case:{parsed}",
            result="blocked",
            reason="Active legal hold.",
        )
        return _json_error("Disposition is blocked by an active legal hold.", 409)
    if len(reason) < 10:
        return _json_error("A disposition reason of at least 10 characters is required.", 400)
    records, _, _ = decoded_setting(_db().session, "governance", "disposition_reviews", [])
    history = records if isinstance(records, list) else []
    record = {
        "id": str(uuid4()),
        "case_id": str(case.id),
        "case_number": case.case_number,
        "status": "approval_required",
        "reason": reason[:1000],
        "created_at": _iso(utc_now()),
        "created_by": _current_username(),
        "deletion_executed": False,
        "secure_erasure_verified": False,
        "detail": "Review only; custody bytes and records were not deleted.",
    }
    history.insert(0, record)
    _set_setting("governance", "disposition_reviews", json.dumps(history[:500]), "json")
    _record_governance_audit(
        "governance.disposition.requested",
        f"case:{case.id}",
        result="success",
        reason=reason[:1000],
    )
    return jsonify(record), 201


@api_v1_blueprint.post("/admin/deployments/verify")
@require_role("admin")
def verify_deployment():  # type: ignore[no-untyped-def]
    checks: list[dict[str, object]] = []

    def check(name: str, required: bool, operation) -> None:
        try:
            detail = operation()
            checks.append({"name": name, "status": "passed", "required": required, "detail": detail})
        except Exception as error:
            checks.append(
                {
                    "name": name,
                    "status": "failed",
                    "required": required,
                    "detail": str(error)[:300],
                }
            )

    check("Database connectivity", True, lambda: str(_db().session.execute(select(1)).scalar_one()))
    check(
        "Evidence storage provider",
        True,
        lambda: _storage_manager().workspace()["provider"]["status"],
    )
    audit_writer = current_app.extensions.get("cyberinvestigator_audit_writer")
    check(
        "Audit chain",
        True,
        lambda: (
            "verified"
            if audit_writer is not None and audit_writer.verify_integrity().get("valid") is True
            else (_ for _ in ()).throw(RuntimeError("Audit chain verification failed."))
        ),
    )
    check(
        "Security controls",
        True,
        lambda: (
            "enabled"
            if current_app.config.get("SECURITY_HEADERS_ENABLED") and current_app.config.get("CSRF_ENABLED")
            else (_ for _ in ()).throw(RuntimeError("Required web security controls are disabled."))
        ),
    )
    release = _deployment_inspector().current_release(str(current_app.config.get("ENVIRONMENT") or "development"))
    check(
        "Release metadata",
        False,
        lambda: (
            release["version"]
            if release.get("git_sha") and release.get("build_time")
            else (_ for _ in ()).throw(RuntimeError("Build revision or build time is unavailable."))
        ),
    )
    required_failures = [item for item in checks if item["required"] and item["status"] == "failed"]
    warnings = [item for item in checks if not item["required"] and item["status"] == "failed"]
    result = {
        "status": "failed" if required_failures else "passed_with_warnings" if warnings else "passed",
        "checks": checks,
        "verified_at": _iso(utc_now()),
        "verified_by": _current_username(),
        "release": release,
    }
    _set_setting("deployment", "last_verification", json.dumps(result), "json")
    _record_deployment_audit(
        "deployment.verification.completed",
        f"release:{release['version']}",
        result="failure" if required_failures else "success",
        reason=f"required_failures:{len(required_failures)} warnings:{len(warnings)}",
    )
    if required_failures:
        _db().session.add(
            SecurityAlert(
                level="high",
                category="deployment",
                title="Deployment verification failed",
                message=f"{len(required_failures)} required deployment checks failed.",
                score=80,
                confidence=100,
            )
        )
        _db().session.add(
            Notification(
                title="Deployment verification failed",
                message=f"{len(required_failures)} required deployment checks need review.",
                category="deployment",
                priority="high",
                pinned=True,
            )
        )
        _db().session.commit()
    return jsonify(result), 409 if required_failures else 200


@api_v1_blueprint.post("/admin/deployments/rollback-plans")
@require_role("admin")
def create_rollback_plan():  # type: ignore[no-untyped-def]
    target_version = str((request.get_json(silent=True) or {}).get("target_version") or "").strip()
    workspace = _deployment_workspace_payload()
    current = workspace["deployment_status"]["release"]
    candidates = workspace["rollback"]["candidates"]
    target = next((item for item in candidates if str(item.get("version")) == target_version), None)
    if target is None or not target.get("digest"):
        _record_deployment_audit(
            "deployment.rollback_plan.rejected",
            f"release:{target_version or 'missing'}",
            result="blocked",
            reason="Target is not a recorded immutable release.",
        )
        return _json_error("Rollback target is not a recorded immutable release.", 409)
    plan = {
        "status": "ready_for_environment_adapter",
        "created_at": _iso(utc_now()),
        "created_by": _current_username(),
        "from_version": current.get("version"),
        "target_version": target.get("version"),
        "target_digest": target.get("digest"),
        "automatic_rollback_executed": False,
        "steps": [
            "Place the environment in maintenance mode.",
            "Create and verify a pre-rollback storage backup.",
            "Redeploy the recorded immutable image digest.",
            "Run deployment and evidence-integrity verification.",
            "Exit maintenance mode only after required checks pass.",
        ],
    }
    history = _setting_json("deployment", "rollback_plans", [])
    records = history if isinstance(history, list) else []
    records.insert(0, plan)
    _set_setting("deployment", "rollback_plans", json.dumps(records[:100]), "json")
    _record_deployment_audit(
        "deployment.rollback_plan.created",
        f"release:{target_version}",
        result="success",
        reason=f"from:{current.get('version')} digest:{target.get('digest')}",
    )
    return jsonify(plan), 201


@api_v1_blueprint.get("/admin/overview")
@require_role("admin")
def admin_overview():  # type: ignore[no-untyped-def]
    settings_payload = get_settings().get_json()
    metrics = monitoring_metrics().get_json()
    session = _db().session
    database = {
        "dialect": _db().engine.dialect.name,
        "uri": str(current_app.config.get("SQLALCHEMY_DATABASE_URI", "")).split("@")[-1],
        "status": "ok",
        "tables": {
            "cases": session.scalar(
                select(func.count()).select_from(Case).where(Case.organization_id == _current_organization_id())
            ),
            "evidence": session.scalar(select(func.count()).select_from(Evidence)),
            "timeline_events": session.scalar(select(func.count()).select_from(TimelineEvent)),
            "reports": session.scalar(select(func.count()).select_from(Report)),
            "settings": session.scalar(select(func.count()).select_from(Setting)),
            "users": session.scalar(select(func.count()).select_from(User)),
            "audit_logs": session.scalar(select(func.count()).select_from(AuditLog)),
            "security_alerts": session.scalar(select(func.count()).select_from(SecurityAlert)),
        },
    }
    logs_dir = Path(current_app.config["LOGS_FOLDER"])
    logs = (
        [
            {"name": path.name, "size_bytes": path.stat().st_size, "updated_at": _iso(utc_now())}
            for path in sorted(logs_dir.glob("*.log"))
        ]
        if logs_dir.exists()
        else []
    )
    users_payload = list_users().get_json()
    permissions = {
        role.name: [item.permission.code for item in role.permissions]
        for role in session.scalars(select(Role).where(Role.name.in_(["admin", "user"])).order_by(Role.name))
    }
    plugins = plugin_inventory().get_json()
    return jsonify(
        {
            "settings": settings_payload["config"],
            "metrics": metrics,
            "health": health_ready()[0].get_json(),
            "database": database,
            "logs": logs,
            "users": users_payload["users"],
            "roles": users_payload["roles"],
            "permissions": permissions,
            "performance": _runtime_metrics(),
            "audit_logs": [
                _audit_log_json(item)
                for item in session.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(40))
            ],
            "background_jobs": list(_analysis_jobs().values())[-100:],
            "plugin_health": plugins,
            "ai_status": _provider_status(),
            "openai_status": _provider_status(),
            "security": _security_overview(),
        }
    )


@api_v1_blueprint.get("/admin/operations")
@require_role("admin")
def admin_operations_center():  # type: ignore[no-untyped-def]
    """Return real operational state without inferred health or fabricated capacity metrics."""
    session = _db().session
    readiness_response, readiness_status = health_ready()
    readiness = readiness_response.get_json()
    alerts = list(
        session.scalars(
            select(SecurityAlert)
            .where(SecurityAlert.status.in_(["open", "acknowledged"]))
            .order_by(SecurityAlert.created_at.desc())
            .limit(100)
        )
    )
    jobs = list(_analysis_jobs().values())
    job_counts = {
        status: sum(1 for item in jobs if item.get("status") == status)
        for status in ("queued", "running", "completed", "failed")
    }
    maintenance_record = session.scalar(
        select(Setting).where(Setting.namespace == "platform", Setting.key == "maintenance")
    )
    try:
        maintenance = json.loads(maintenance_record.value) if maintenance_record else {"enabled": False, "message": ""}
    except (TypeError, json.JSONDecodeError):
        maintenance = {"enabled": False, "message": "", "state": "invalid_configuration"}
    failed_requests = (
        session.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.result.in_(["failure", "blocked"])))
        or 0
    )
    integrity_writer = current_app.extensions.get("cyberinvestigator_audit_writer")
    integrity = (
        integrity_writer.verify_integrity()
        if integrity_writer is not None and hasattr(integrity_writer, "verify_integrity")
        else {"valid": None, "reason": "Audit writer unavailable."}
    )
    return jsonify(
        {
            "status": "maintenance"
            if maintenance.get("enabled")
            else "operational"
            if readiness_status == 200
            else "degraded",
            "health": readiness,
            "critical_alerts": [_security_alert_json(item) for item in alerts if item.level in {"critical", "high"}],
            "active_issues": [_security_alert_json(item) for item in alerts],
            "metrics": {
                "entities": {
                    "users": session.scalar(select(func.count()).select_from(User)) or 0,
                    "cases": session.scalar(
                        select(func.count()).select_from(Case).where(Case.organization_id == _current_organization_id())
                    )
                    or 0,
                    "evidence": session.scalar(select(func.count()).select_from(Evidence)) or 0,
                    "reports": session.scalar(select(func.count()).select_from(Report)) or 0,
                },
                "jobs": job_counts,
                "failed_or_blocked_audit_events": failed_requests,
                "open_alerts": len(alerts),
            },
            "resource_usage": {
                "process_uptime_seconds": _runtime_metrics().get("uptime_seconds"),
                "memory": {"status": "unavailable", "reason": "No process memory collector is configured."},
                "cpu": {"status": "unavailable", "reason": "No process CPU collector is configured."},
                "storage": _storage_manager().workspace()["capacity"],
            },
            "jobs": jobs[-100:],
            "maintenance": maintenance,
            "audit_integrity": integrity,
            "activity": [
                _audit_log_json(item)
                for item in session.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(50))
            ],
            "collected_at": utc_now().isoformat(),
        }
    )


@api_v1_blueprint.patch("/admin/alerts/<alert_id>")
@require_role("admin")
def update_security_alert(alert_id: str):  # type: ignore[no-untyped-def]
    try:
        alert = _db().session.get(SecurityAlert, _uuid(alert_id, "alert_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if alert is None:
        return _json_error("Security alert was not found.", 404)
    status = str((request.get_json(silent=True) or {}).get("status") or "").strip().lower()
    if status not in {"open", "acknowledged", "resolved"}:
        return _json_error("Alert status must be open, acknowledged, or resolved.", 400)
    alert.status = status
    _db().session.commit()
    _record_account_audit(
        f"admin.security_alert.{status}",
        f"security_alert:{alert.id}",
        reason=f"{alert.level}:{alert.category}",
    )
    return jsonify(_security_alert_json(alert))


@api_v1_blueprint.route("/admin/maintenance", methods=["GET", "PATCH"])
@require_role("admin")
def admin_maintenance():  # type: ignore[no-untyped-def]
    session = _db().session
    record = session.scalar(select(Setting).where(Setting.namespace == "platform", Setting.key == "maintenance"))
    if request.method == "GET":
        try:
            state = json.loads(record.value) if record else {"enabled": False, "message": ""}
        except (TypeError, json.JSONDecodeError):
            state = {"enabled": False, "message": "", "state": "invalid_configuration"}
        return jsonify(state)
    document = request.get_json(silent=True) or {}
    state = {
        "enabled": bool(document.get("enabled")),
        "message": _normalize_text(document.get("message"), limit=500)
        or "The platform is temporarily unavailable for maintenance.",
        "updated_at": utc_now().isoformat(),
        "updated_by": _current_username(),
    }
    _set_setting("platform", "maintenance", json.dumps(state), "json")
    session.commit()
    _record_account_audit(
        "admin.maintenance.enabled" if state["enabled"] else "admin.maintenance.disabled",
        "platform:maintenance",
        reason=state["message"],
    )
    return jsonify(state)


@api_v1_blueprint.get("/admin/logs")
@require_role("admin")
def admin_logs():  # type: ignore[no-untyped-def]
    name = Path(request.args.get("name", "cyberinvestigator.log")).name
    return jsonify({"name": name, "lines": _tail_file(Path(current_app.config["LOGS_FOLDER"]) / name, lines=200)})


@api_v1_blueprint.get("/admin/audit-logs")
@require_role("admin")
def admin_audit_logs():  # type: ignore[no-untyped-def]
    session = _db().session
    q = _query_text()
    level = request.args.get("result", "all")
    rows = list(session.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(500)))
    if level != "all":
        rows = [item for item in rows if item.result == level]
    if q:
        rows = [item for item in rows if q in json.dumps(_audit_log_json(item), default=str).lower()]
    return jsonify({"items": [_audit_log_json(item) for item in rows[:200]]})


@api_v1_blueprint.get("/admin/database")
@require_role("admin")
def admin_database():  # type: ignore[no-untyped-def]
    session = _db().session
    session.execute(text("SELECT 1")).scalar_one()
    return jsonify(
        {
            "status": "ok",
            "dialect": _db().engine.dialect.name,
            "tables": {
                "cases": session.scalar(
                    select(func.count()).select_from(Case).where(Case.organization_id == _current_organization_id())
                ),
                "evidence": session.scalar(select(func.count()).select_from(Evidence)),
                "timeline_events": session.scalar(select(func.count()).select_from(TimelineEvent)),
                "reports": session.scalar(select(func.count()).select_from(Report)),
            },
        }
    )


@api_v1_blueprint.get("/admin/users")
@require_role("admin")
def list_users():  # type: ignore[no-untyped-def]
    session = _db().session
    q = _query_text()
    status = request.args.get("status", "all")
    role = request.args.get("role", "all")
    users = list(session.scalars(select(User).order_by(User.created_at.desc()).limit(500)))
    if status != "all":
        users = [item for item in users if item.status == status]
    if role != "all":
        users = [item for item in users if item.role.name == role]
    if q:
        users = [item for item in users if q in f"{item.username} {item.email}".lower()]
    roles = [
        {
            "id": str(item.id),
            "name": item.name,
            "permissions": [mapping.permission.code for mapping in item.permissions],
        }
        for item in session.scalars(select(Role).where(Role.name.in_(["admin", "user"])).order_by(Role.name))
    ]
    return jsonify({"users": [_user_json(item) for item in users], "roles": roles})


def _managed_session_json(item: UserSession) -> dict[str, object]:
    active = _managed_session_active(item)
    return {
        "id": str(item.id),
        "user_id": str(item.user_id),
        "status": "expired" if item.active and not active else item.status,
        "active": active,
        "ip_address": item.ip_address,
        "user_agent": item.user_agent,
        "created_at": _iso(item.created_at),
        "updated_at": _iso(item.updated_at),
        "last_seen_at": _iso(item.last_seen_at),
        "expires_at": _iso(item.expires_at),
    }


def _managed_session_active(item: UserSession) -> bool:
    expires_at = item.expires_at
    now = utc_now()
    if expires_at.tzinfo is None:
        now = now.replace(tzinfo=None)
    return bool(item.active and expires_at > now)


def _role_json(role: Role) -> dict[str, object]:
    return {
        "id": str(role.id),
        "name": role.name,
        "description": role.description,
        "is_system": role.is_system,
        "user_count": len(role.users),
        "permissions": sorted(item.permission.code for item in role.permissions),
    }


@api_v1_blueprint.get("/admin/identity")
@require_role("admin")
def identity_workspace():  # type: ignore[no-untyped-def]
    """Return persisted IAM state, never inferred users, grants, or sessions."""
    session = _db().session
    users = list(session.scalars(select(User).order_by(User.created_at.desc()).limit(500)))
    roles = list(session.scalars(select(Role).order_by(Role.is_system.desc(), Role.name)))
    permissions = list(session.scalars(select(Permission).order_by(Permission.category, Permission.code)))
    active_sessions = (
        session.scalar(
            select(func.count())
            .select_from(UserSession)
            .where(UserSession.active.is_(True), UserSession.expires_at > utc_now())
        )
        or 0
    )
    locked_users = session.scalar(select(func.count()).select_from(User).where(User.locked_until.is_not(None))) or 0
    return jsonify(
        {
            "summary": {
                "users": len(users),
                "active_users": sum(item.status == "active" for item in users),
                "locked_users": locked_users,
                "active_sessions": active_sessions,
                "roles": len(roles),
                "permissions": len(permissions),
            },
            "users": [_user_json(item) for item in users],
            "roles": [_role_json(item) for item in roles],
            "permissions": [
                {
                    "id": str(item.id),
                    "code": item.code,
                    "label": item.label,
                    "category": item.category,
                }
                for item in permissions
            ],
            "capabilities": {
                "mfa": {"status": "not_configured"},
                "sso": {"status": "not_configured"},
                "directory": {"status": "not_configured"},
            },
        }
    )


@api_v1_blueprint.get("/admin/identity/users/<user_id>")
@require_role("admin")
def identity_user_detail(user_id: str):  # type: ignore[no-untyped-def]
    try:
        user = _db().session.get(User, _uuid(user_id, "user_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if user is None:
        return _json_error("User was not found.", 404)
    sessions = list(
        _db().session.scalars(
            select(UserSession).where(UserSession.user_id == user.id).order_by(UserSession.created_at.desc()).limit(100)
        )
    )
    activity = list(
        _db().session.scalars(
            select(AuditLog).where(AuditLog.user_id == user.id).order_by(AuditLog.created_at.desc()).limit(50)
        )
    )
    return jsonify(
        {
            "user": _user_json(user),
            "permissions": sorted(item.permission.code for item in user.role.permissions),
            "sessions": [_managed_session_json(item) for item in sessions],
            "security": {
                "failed_login_count": user.failed_login_count,
                "locked_until": _iso(user.locked_until),
                "active_sessions": sum(_managed_session_active(item) for item in sessions),
                "last_login_at": _iso(user.last_login_at),
            },
            "activity": [_audit_log_json(item) for item in activity],
        }
    )


@api_v1_blueprint.post("/admin/roles")
@require_role("admin")
def create_role():  # type: ignore[no-untyped-def]
    document = request.get_json(silent=True) or {}
    name = str(document.get("name") or "").strip().lower()
    description = _normalize_text(document.get("description"), limit=2000)
    if not re.fullmatch(r"[a-z][a-z0-9_-]{2,63}", name):
        return _json_error("Role name must be 3-64 lowercase letters, numbers, underscores, or hyphens.", 400)
    session = _db().session
    if session.scalar(select(Role).where(Role.name == name)):
        return _json_error("Role already exists.", 409)
    permission_codes = {str(item) for item in document.get("permission_codes", [])}
    permissions = list(session.scalars(select(Permission).where(Permission.code.in_(permission_codes))))
    if len(permissions) != len(permission_codes):
        return _json_error("One or more permissions were not found.", 400)
    role = Role(name=name, description=description, is_system=False)
    session.add(role)
    session.flush()
    session.add_all(RolePermission(role_id=role.id, permission_id=item.id) for item in permissions)
    session.commit()
    _record_account_audit(
        "admin.role.created",
        f"role:{role.id}",
        reason=f"{name}; permissions={','.join(sorted(permission_codes)) or 'none'}",
    )
    return jsonify(_role_json(role)), 201


@api_v1_blueprint.patch("/admin/roles/<role_id>")
@require_role("admin")
def update_role(role_id: str):  # type: ignore[no-untyped-def]
    try:
        role = _db().session.get(Role, _uuid(role_id, "role_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if role is None:
        return _json_error("Role was not found.", 404)
    document = request.get_json(silent=True) or {}
    if "description" in document:
        role.description = _normalize_text(document.get("description"), limit=2000)
    if "permission_codes" in document:
        permission_codes = {str(item) for item in document.get("permission_codes", [])}
        if role.name == "admin" and not {"admin.access", "users.manage"}.issubset(permission_codes):
            return _json_error("The system administrator role must retain admin.access and users.manage.", 409)
        permissions = list(_db().session.scalars(select(Permission).where(Permission.code.in_(permission_codes))))
        if len(permissions) != len(permission_codes):
            return _json_error("One or more permissions were not found.", 400)
        role.permissions.clear()
        _db().session.flush()
        role.permissions.extend(RolePermission(role_id=role.id, permission_id=item.id) for item in permissions)
    _db().session.commit()
    _record_account_audit(
        "admin.role.updated",
        f"role:{role.id}",
        reason=f"{role.name}; fields={','.join(sorted(document)) or 'none'}",
    )
    return jsonify(_role_json(role))


@api_v1_blueprint.delete("/admin/roles/<role_id>")
@require_role("admin")
def delete_role(role_id: str):  # type: ignore[no-untyped-def]
    try:
        role = _db().session.get(Role, _uuid(role_id, "role_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if role is None:
        return _json_error("Role was not found.", 404)
    if role.is_system:
        return _json_error("System roles cannot be deleted.", 409)
    if role.users:
        return _json_error("Reassign all users before deleting this role.", 409)
    affected_object = f"role:{role.id}"
    role_name = role.name
    _db().session.delete(role)
    _db().session.commit()
    _record_account_audit(
        "admin.role.deleted",
        affected_object,
        reason=role_name,
    )
    return jsonify({"deleted": True, "id": role_id, "name": role_name})


@api_v1_blueprint.delete("/admin/identity/sessions/<session_id>")
@require_role("admin")
def revoke_managed_session(session_id: str):  # type: ignore[no-untyped-def]
    try:
        record = _db().session.get(UserSession, _uuid(session_id, "session_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if record is None:
        return _json_error("Session was not found.", 404)
    record.active = False
    record.status = "revoked"
    record.updated_at = utc_now()
    _db().session.commit()
    _record_account_audit(
        "admin.session.revoked",
        f"session:{record.id}",
        reason=f"user:{record.user_id}",
    )
    return jsonify(_managed_session_json(record))


@api_v1_blueprint.post("/admin/users")
@require_role("admin")
def create_user():  # type: ignore[no-untyped-def]
    data = request.get_json(silent=True) or {}
    username = _normalize_text(data.get("username"), limit=80)
    email = _normalize_text(data.get("email"), limit=255)
    password = str(data.get("password") or "")
    role_name = str(data.get("role") or "user").strip().lower()
    if role_name == "administrator":
        role_name = "admin"
    if not username or not email or len(password) < 10:
        return _json_error("username, email, and a password of at least 10 characters are required.", 400)
    session = _db().session
    role = session.scalar(select(Role).where(Role.name == role_name))
    if role is None:
        return _json_error("Role was not found.", 404)
    if session.scalar(
        select(User).where((func.lower(User.username) == username.lower()) | (func.lower(User.email) == email.lower()))
    ):
        return _json_error("user already exists.", 409)
    user = User(username=username, email=email, password_hash=hash_password(password), role_id=role.id, status="active")
    session.add(user)
    session.flush()
    session.commit()
    _record_account_audit(
        "admin.user.create",
        f"user:{user.id}",
        reason=f"Created account {user.username} with role {role_name}.",
    )
    return jsonify({"user": _user_json(user)}), 201


@api_v1_blueprint.patch("/admin/users/<user_id>")
@require_role("admin")
def update_user(user_id: str):  # type: ignore[no-untyped-def]
    data = request.get_json(silent=True) or {}
    session = _db().session
    user = session.get(User, _uuid(user_id))
    if user is None:
        return _json_error("user was not found.", 404)
    actor_id = _current_user_id()
    if actor_id == user.id and (
        data.get("status") in {"disabled", "suspended"}
        or ("role" in data and str(data["role"]).strip().lower() != user.role.name)
    ):
        return _json_error("Administrators cannot disable or change their own role.", 409)
    if "status" in data:
        status = str(data["status"])
        if status not in {"active", "disabled", "suspended"}:
            return _json_error("status must be active, disabled, or suspended.", 400)
        if user.role.name == "admin" and status != "active":
            other_admins = (
                session.scalar(
                    select(func.count())
                    .select_from(User)
                    .join(Role)
                    .where(Role.name == "admin", User.status == "active", User.id != user.id)
                )
                or 0
            )
            if other_admins == 0:
                return _json_error("The final active administrator cannot be disabled.", 409)
        user.status = status
    if "role" in data:
        role_name = str(data["role"]).strip().lower()
        if role_name == "administrator":
            role_name = "admin"
        role = session.scalar(select(Role).where(Role.name == role_name))
        if role is None:
            return _json_error("Role was not found.", 404)
        if user.role.name == "admin" and role.name != "admin" and user.status == "active":
            other_admins = (
                session.scalar(
                    select(func.count())
                    .select_from(User)
                    .join(Role)
                    .where(Role.name == "admin", User.status == "active", User.id != user.id)
                )
                or 0
            )
            if other_admins == 0:
                return _json_error("The final active administrator cannot be reassigned.", 409)
        user.role_id = role.id
    if "password" in data and str(data["password"]):
        if len(str(data["password"])) < 10:
            return _json_error("password must contain at least 10 characters.", 400)
        user.password_hash = hash_password(str(data["password"]))
    if data.get("unlock") is True:
        user.failed_login_count = 0
        user.locked_until = None
    if user.status != "active" or ("password" in data and str(data["password"])):
        for managed_session in session.scalars(
            select(UserSession).where(UserSession.user_id == user.id, UserSession.active.is_(True))
        ):
            managed_session.active = False
            managed_session.status = "revoked"
            managed_session.updated_at = utc_now()
    session.commit()
    changed_fields = sorted(key for key in ("status", "role", "password", "unlock") if key in data)
    _record_account_audit(
        "admin.user.update",
        f"user:{user.id}",
        reason=f"Updated {user.username}: {', '.join(changed_fields) or 'no fields'}.",
    )
    return jsonify({"user": _user_json(user)})


@api_v1_blueprint.get("/admin/secrets")
@require_role("admin")
def secrets_inventory():  # type: ignore[no-untyped-def]
    refs = [item.strip() for item in str(current_app.config.get("SECRET_REFERENCES", "")).split(",") if item.strip()]
    configured = {
        "ai_api_key": bool(current_app.config.get("AI_API_KEY")),
        "secret_key": bool(current_app.config.get("SECRET_KEY")),
        "healthcheck_token": bool(current_app.config.get("HEALTHCHECK_TOKEN")),
    }
    return jsonify({"configured": configured, "external_references": refs, "values_exposed": False})


def _collaboration_case(case_id: str):
    try:
        parsed = _uuid(case_id, "case_id")
    except ValueError as error:
        return None, _json_error(str(error), 400)
    case = _db().session.get(Case, parsed)
    if case is None or case.deleted_at is not None:
        return None, _json_error("Case was not found.", 404)
    if not _case_accessible(parsed):
        return None, _json_error("Case access is forbidden.", 403)
    return case, None


def _can_manage_case_team(case: Case) -> bool:
    actor = _current_user_id()
    if _is_admin() or (actor is not None and case.owner_user_id == actor):
        return True
    return bool(
        actor
        and _db().session.scalar(
            select(CaseTeamMember.id).where(
                CaseTeamMember.case_id == case.id,
                CaseTeamMember.organization_id == _current_organization_id(),
                CaseTeamMember.user_id == actor,
                CaseTeamMember.status == "active",
                CaseTeamMember.team_role == "lead",
            )
        )
    )


def _case_team_role(case: Case, user_id: UUID | None = None) -> str | None:
    actor = user_id or _current_user_id()
    if actor is None:
        return None
    if actor == case.owner_user_id:
        return "owner"
    if actor == case.reviewer_user_id:
        return "reviewer"
    return _db().session.scalar(
        select(CaseTeamMember.team_role).where(
            CaseTeamMember.case_id == case.id,
            CaseTeamMember.organization_id == _current_organization_id(),
            CaseTeamMember.user_id == actor,
            CaseTeamMember.status == "active",
        )
    )


def _can_write_collaboration(case: Case) -> bool:
    return _is_admin() or _case_team_role(case) in {"owner", "lead", "investigator", "reviewer"}


def _organization_user(user_id: UUID) -> User | None:
    return _db().session.scalar(
        select(User)
        .join(OrganizationMembership, OrganizationMembership.user_id == User.id)
        .where(
            User.id == user_id,
            User.status == "active",
            OrganizationMembership.organization_id == _current_organization_id(),
            OrganizationMembership.status == "active",
        )
    )


def _collaboration_audit(action: str, affected_object: str, reason: str | None = None) -> None:
    _db().session.add(
        AuditLog(
            organization_id=_current_organization_id(),
            user_id=_current_user_id(),
            username=_current_username(),
            role=_current_user_role(),
            action=action,
            result="success",
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            affected_object=affected_object,
            reason=reason,
        )
    )


def _collaboration_notification(user_id: UUID | None, title: str, message: str, category: str) -> None:
    if user_id is None or user_id == _current_user_id():
        return
    _db().session.add(
        Notification(
            organization_id=_current_organization_id(),
            user_id=user_id,
            owner_user_id=user_id,
            created_by_user_id=_current_user_id(),
            title=title,
            message=message,
            category=category,
            priority="info",
        )
    )


def _team_json(member: CaseTeamMember) -> dict[str, object]:
    user = _db().session.get(User, member.user_id)
    return {
        "id": str(member.id),
        "user_id": str(member.user_id),
        "username": user.username if user else "Unavailable user",
        "team_role": member.team_role,
        "status": member.status,
        "created_at": member.created_at.isoformat(),
    }


def _task_json(task: CollaborationTask) -> dict[str, object]:
    assignee = _db().session.get(User, task.assignee_user_id) if task.assignee_user_id else None
    return {
        "id": str(task.id),
        "case_id": str(task.case_id),
        "title": task.title,
        "description": task.description,
        "status": task.status,
        "priority": task.priority,
        "assignee_user_id": str(task.assignee_user_id) if task.assignee_user_id else None,
        "assignee": assignee.username if assignee else None,
        "due_at": task.due_at.isoformat() if task.due_at else None,
        "completed_at": task.completed_at.isoformat() if task.completed_at else None,
        "updated_at": task.updated_at.isoformat(),
    }


def _notification_json(notification: Notification) -> dict[str, object]:
    """Serialize a notification consistently across account and mobile surfaces."""
    return {
        "id": str(notification.id),
        "title": notification.title,
        "message": notification.message,
        "category": notification.category,
        "priority": notification.priority,
        "read": notification.read,
        "pinned": notification.pinned,
        "archived": notification.archived,
        "status": notification.status,
        "owner_user_id": str(notification.owner_user_id) if notification.owner_user_id else None,
        "created_by": str(notification.created_by_user_id) if notification.created_by_user_id else None,
        "created_at": _iso(notification.created_at),
        "updated_at": _iso(notification.updated_at),
    }


def _comment_json(comment: DiscussionComment) -> dict[str, object]:
    author = _db().session.get(User, comment.author_user_id) if comment.author_user_id else None
    return {
        "id": str(comment.id),
        "thread_id": str(comment.thread_id),
        "parent_comment_id": str(comment.parent_comment_id) if comment.parent_comment_id else None,
        "author_user_id": str(comment.author_user_id) if comment.author_user_id else None,
        "author": author.username if author else "Unavailable user",
        "body": comment.body,
        "visibility": comment.visibility,
        "created_at": comment.created_at.isoformat(),
        "updated_at": comment.updated_at.isoformat(),
    }


def _review_json(review: CaseReview) -> dict[str, object]:
    reviewer = _db().session.get(User, review.reviewer_user_id)
    return {
        "id": str(review.id),
        "case_id": str(review.case_id),
        "reviewer_user_id": str(review.reviewer_user_id),
        "reviewer": reviewer.username if reviewer else "Unavailable user",
        "status": review.status,
        "request_note": review.request_note,
        "decision_note": review.decision_note,
        "decided_at": review.decided_at.isoformat() if review.decided_at else None,
        "created_at": review.created_at.isoformat(),
        "updated_at": review.updated_at.isoformat(),
    }


def _visible_comments(case_id: UUID, thread_id: UUID | None = None) -> list[DiscussionComment]:
    actor = _current_user_id()
    statement = select(DiscussionComment).where(
        DiscussionComment.organization_id == _current_organization_id(),
        DiscussionComment.case_id == case_id,
        DiscussionComment.status == "active",
        (DiscussionComment.visibility == "team") | (DiscussionComment.author_user_id == actor),
    )
    if thread_id is not None:
        statement = statement.where(DiscussionComment.thread_id == thread_id)
    return list(_db().session.scalars(statement.order_by(DiscussionComment.created_at)))


def _case_collaboration_payload(case: Case) -> dict[str, object]:
    organization_id = _current_organization_id()
    members = list(
        _db().session.scalars(
            select(CaseTeamMember).where(
                CaseTeamMember.organization_id == organization_id,
                CaseTeamMember.case_id == case.id,
                CaseTeamMember.status == "active",
            )
        )
    )
    tasks = list(
        _db().session.scalars(
            select(CollaborationTask)
            .where(CollaborationTask.organization_id == organization_id, CollaborationTask.case_id == case.id)
            .order_by(CollaborationTask.created_at.desc())
        )
    )
    threads = list(
        _db().session.scalars(
            select(DiscussionThread)
            .where(DiscussionThread.organization_id == organization_id, DiscussionThread.case_id == case.id)
            .order_by(DiscussionThread.updated_at.desc())
        )
    )
    reviews = list(
        _db().session.scalars(
            select(CaseReview)
            .where(CaseReview.organization_id == organization_id, CaseReview.case_id == case.id)
            .order_by(CaseReview.created_at.desc())
        )
    )
    visible = _visible_comments(case.id)
    comments_by_thread: dict[UUID, list[dict[str, object]]] = {}
    for comment in visible:
        comments_by_thread.setdefault(comment.thread_id, []).append(_comment_json(comment))
    return {
        "case": {"id": str(case.id), "case_number": case.case_number, "title": case.title},
        "team": [_team_json(item) for item in members],
        "tasks": [_task_json(item) for item in tasks],
        "threads": [
            {
                "id": str(thread.id),
                "title": thread.title,
                "status": thread.status,
                "updated_at": thread.updated_at.isoformat(),
                "comments": comments_by_thread.get(thread.id, []),
            }
            for thread in threads
        ],
        "reviews": [_review_json(item) for item in reviews],
    }


@api_v1_blueprint.get("/collaboration")
def collaboration_workspace():  # type: ignore[no-untyped-def]
    """Return real assigned work and activity for the active user and tenant."""
    actor = _current_user_id()
    case_ids = _owned_case_ids()
    assigned_tasks = (
        list(
            _db().session.scalars(
                select(CollaborationTask)
                .where(
                    CollaborationTask.organization_id == _current_organization_id(),
                    CollaborationTask.assignee_user_id == actor,
                )
                .order_by(CollaborationTask.updated_at.desc())
            )
        )
        if actor
        else []
    )
    comments = []
    if case_ids:
        comments = _visible_comments_for_cases(case_ids)
    updates = [
        {
            "id": str(item.id),
            "case_id": str(item.case_id),
            "author": (
                _db().session.get(User, item.author_user_id).username
                if item.author_user_id and _db().session.get(User, item.author_user_id)
                else "Unavailable user"
            ),
            "body": item.body,
            "created_at": item.created_at.isoformat(),
        }
        for item in comments[-30:]
    ]
    username = _current_username().lower()
    mentions = [item for item in updates if f"@{username}" in str(item["body"]).lower()]
    return jsonify(
        {
            "assigned_tasks": [_task_json(item) for item in assigned_tasks],
            "investigation_updates": updates,
            "comments": updates,
            "mentions": mentions,
        }
    )


def _visible_comments_for_cases(case_ids: set[UUID]) -> list[DiscussionComment]:
    actor = _current_user_id()
    return list(
        _db().session.scalars(
            select(DiscussionComment)
            .where(
                DiscussionComment.organization_id == _current_organization_id(),
                DiscussionComment.case_id.in_(case_ids),
                DiscussionComment.status == "active",
                (DiscussionComment.visibility == "team") | (DiscussionComment.author_user_id == actor),
            )
            .order_by(DiscussionComment.created_at.desc())
        )
    )


@api_v1_blueprint.get("/cases/<case_id>/collaboration")
def case_collaboration(case_id: str):  # type: ignore[no-untyped-def]
    case, error = _collaboration_case(case_id)
    return error or jsonify(_case_collaboration_payload(case))


@api_v1_blueprint.post("/cases/<case_id>/team")
def add_case_team_member(case_id: str):  # type: ignore[no-untyped-def]
    case, error = _collaboration_case(case_id)
    if error:
        return error
    if not _can_manage_case_team(case):
        return _json_error("Only the case owner, team lead, or administrator may manage the team.", 403)
    data = request.get_json(silent=True) or {}
    try:
        user_id = _uuid(str(data.get("user_id", "")), "user_id")
    except ValueError as exc:
        return _json_error(str(exc), 400)
    user = _organization_user(user_id)
    if user is None:
        return _json_error("Active organization member was not found.", 404)
    team_role = str(data.get("team_role", "investigator")).lower()
    if team_role not in {"lead", "investigator", "reviewer", "observer"}:
        return _json_error("team_role must be lead, investigator, reviewer, or observer.", 400)
    member = _db().session.scalar(
        select(CaseTeamMember).where(CaseTeamMember.case_id == case.id, CaseTeamMember.user_id == user_id)
    )
    if member is None:
        member = CaseTeamMember(
            organization_id=_current_organization_id(),
            case_id=case.id,
            user_id=user_id,
            team_role=team_role,
            added_by_user_id=_current_user_id(),
        )
        _db().session.add(member)
    else:
        member.team_role = team_role
        member.status = "active"
    _collaboration_notification(user_id, f"Added to {case.case_number}", case.title, "assignment")
    _collaboration_audit("collaboration.team_member.added", f"case:{case.id}", f"user:{user_id}; role:{team_role}")
    _db().session.commit()
    return jsonify(_team_json(member)), 201


@api_v1_blueprint.post("/cases/<case_id>/tasks")
def create_collaboration_task(case_id: str):  # type: ignore[no-untyped-def]
    case, error = _collaboration_case(case_id)
    if error:
        return error
    if not _can_write_collaboration(case):
        return _json_error("The case collaboration role is read-only.", 403)
    data = request.get_json(silent=True) or {}
    title = _normalize_text(data.get("title"), limit=255)
    if not title:
        return _json_error("title is required.", 400)
    assignee_id = None
    if data.get("assignee_user_id"):
        try:
            assignee_id = _uuid(str(data["assignee_user_id"]), "assignee_user_id")
        except ValueError as exc:
            return _json_error(str(exc), 400)
        if _organization_user(assignee_id) is None:
            return _json_error("Active organization member was not found.", 404)
        if _case_team_role(case, assignee_id) is None:
            return _json_error("Task assignee must be an active case participant.", 409)
    priority = str(data.get("priority", "medium")).lower()
    if priority not in {"low", "medium", "high", "critical"}:
        return _json_error("priority must be low, medium, high, or critical.", 400)
    due_at = None
    if data.get("due_at"):
        try:
            due_at = datetime.fromisoformat(str(data["due_at"]).replace("Z", "+00:00"))
        except ValueError:
            return _json_error("due_at must be an ISO 8601 timestamp.", 400)
    task = CollaborationTask(
        organization_id=_current_organization_id(),
        case_id=case.id,
        title=title,
        description=_normalize_text(data.get("description"), limit=10_000),
        priority=priority,
        assignee_user_id=assignee_id,
        created_by_user_id=_current_user_id(),
        due_at=due_at,
    )
    _db().session.add(task)
    _db().session.flush()
    _collaboration_notification(assignee_id, f"Task assigned: {title}", case.case_number, "assignment")
    _collaboration_audit("collaboration.task.created", f"task:{task.id}", f"case:{case.id}")
    _db().session.commit()
    return jsonify(_task_json(task)), 201


@api_v1_blueprint.patch("/collaboration/tasks/<task_id>")
def update_collaboration_task(task_id: str):  # type: ignore[no-untyped-def]
    try:
        task = _db().session.get(CollaborationTask, _uuid(task_id, "task_id"))
    except ValueError as exc:
        return _json_error(str(exc), 400)
    if task is None or task.organization_id != _current_organization_id() or not _case_accessible(task.case_id):
        return _json_error("Task was not found.", 404)
    actor = _current_user_id()
    case = _db().session.get(Case, task.case_id)
    if actor != task.assignee_user_id and not _can_manage_case_team(case):
        return _json_error("Only the assignee or case manager may update this task.", 403)
    data = request.get_json(silent=True) or {}
    status = str(data.get("status", task.status)).lower()
    if status not in {"open", "in_progress", "blocked", "completed", "cancelled"}:
        return _json_error("Invalid task status.", 400)
    previous = task.status
    task.status = status
    task.completed_at = utc_now() if status == "completed" else None
    task.updated_at = utc_now()
    _collaboration_audit("collaboration.task.updated", f"task:{task.id}", f"{previous}->{status}")
    _db().session.commit()
    return jsonify(_task_json(task))


@api_v1_blueprint.post("/cases/<case_id>/discussions")
def create_discussion_thread(case_id: str):  # type: ignore[no-untyped-def]
    case, error = _collaboration_case(case_id)
    if error:
        return error
    if not _can_write_collaboration(case):
        return _json_error("The case collaboration role is read-only.", 403)
    data = request.get_json(silent=True) or {}
    title = _normalize_text(data.get("title"), limit=255)
    if not title:
        return _json_error("title is required.", 400)
    thread = DiscussionThread(
        organization_id=_current_organization_id(),
        case_id=case.id,
        title=title,
        created_by_user_id=_current_user_id(),
    )
    _db().session.add(thread)
    _db().session.flush()
    _collaboration_audit("collaboration.discussion.created", f"discussion:{thread.id}", f"case:{case.id}")
    _db().session.commit()
    return jsonify({"id": str(thread.id), "title": thread.title, "status": thread.status}), 201


@api_v1_blueprint.post("/collaboration/discussions/<thread_id>/comments")
def create_discussion_comment(thread_id: str):  # type: ignore[no-untyped-def]
    try:
        thread = _db().session.get(DiscussionThread, _uuid(thread_id, "thread_id"))
    except ValueError as exc:
        return _json_error(str(exc), 400)
    if thread is None or thread.organization_id != _current_organization_id() or not _case_accessible(thread.case_id):
        return _json_error("Discussion was not found.", 404)
    case = _db().session.get(Case, thread.case_id)
    if not _can_write_collaboration(case):
        return _json_error("The case collaboration role is read-only.", 403)
    data = request.get_json(silent=True) or {}
    body = _normalize_text(data.get("body"), limit=20_000)
    if not body:
        return _json_error("body is required.", 400)
    visibility = str(data.get("visibility", "team")).lower()
    if visibility not in {"team", "private"}:
        return _json_error("visibility must be team or private.", 400)
    parent_id = None
    if data.get("parent_comment_id"):
        try:
            parent_id = _uuid(str(data["parent_comment_id"]), "parent_comment_id")
        except ValueError as exc:
            return _json_error(str(exc), 400)
        parent = _db().session.get(DiscussionComment, parent_id)
        if parent is None or parent.thread_id != thread.id:
            return _json_error("Parent comment was not found in this discussion.", 404)
    comment = DiscussionComment(
        organization_id=_current_organization_id(),
        case_id=thread.case_id,
        thread_id=thread.id,
        parent_comment_id=parent_id,
        author_user_id=_current_user_id(),
        body=body,
        visibility=visibility,
    )
    _db().session.add(comment)
    thread.updated_at = utc_now()
    _db().session.flush()
    mentioned = set(re.findall(r"@([A-Za-z0-9_.-]{1,80})", body)) if visibility == "team" else set()
    for username in mentioned:
        user = _db().session.scalar(
            select(User)
            .join(CaseTeamMember, CaseTeamMember.user_id == User.id)
            .where(
                func.lower(User.username) == username.lower(),
                CaseTeamMember.case_id == thread.case_id,
                CaseTeamMember.organization_id == _current_organization_id(),
                CaseTeamMember.status == "active",
            )
        )
        if user:
            _collaboration_notification(user.id, "Mentioned in an investigation", f"case:{thread.case_id}", "mention")
    _collaboration_audit(
        "collaboration.comment.created",
        f"comment:{comment.id}",
        f"case:{thread.case_id}; visibility:{visibility}",
    )
    _db().session.commit()
    return jsonify(_comment_json(comment)), 201


@api_v1_blueprint.post("/cases/<case_id>/reviews")
def request_case_review(case_id: str):  # type: ignore[no-untyped-def]
    case, error = _collaboration_case(case_id)
    if error:
        return error
    if not _can_write_collaboration(case):
        return _json_error("The case collaboration role is read-only.", 403)
    data = request.get_json(silent=True) or {}
    try:
        reviewer_id = _uuid(str(data.get("reviewer_user_id", "")), "reviewer_user_id")
    except ValueError as exc:
        return _json_error(str(exc), 400)
    if _organization_user(reviewer_id) is None:
        return _json_error("Active organization reviewer was not found.", 404)
    review = CaseReview(
        organization_id=_current_organization_id(),
        case_id=case.id,
        requested_by_user_id=_current_user_id(),
        reviewer_user_id=reviewer_id,
        request_note=_normalize_text(data.get("request_note"), limit=10_000),
    )
    case.reviewer_user_id = reviewer_id
    case.review_status = "in_review"
    _db().session.add(review)
    _db().session.flush()
    _collaboration_notification(reviewer_id, f"Review requested: {case.case_number}", case.title, "review")
    _collaboration_audit("collaboration.review.requested", f"review:{review.id}", f"case:{case.id}")
    _db().session.commit()
    return jsonify(_review_json(review)), 201


@api_v1_blueprint.patch("/collaboration/reviews/<review_id>")
def decide_case_review(review_id: str):  # type: ignore[no-untyped-def]
    try:
        review = _db().session.get(CaseReview, _uuid(review_id, "review_id"))
    except ValueError as exc:
        return _json_error(str(exc), 400)
    if review is None or review.organization_id != _current_organization_id() or not _case_accessible(review.case_id):
        return _json_error("Review was not found.", 404)
    if not _is_admin() and review.reviewer_user_id != _current_user_id():
        return _json_error("Only the assigned reviewer may decide this review.", 403)
    data = request.get_json(silent=True) or {}
    decision = str(data.get("decision", "")).lower()
    if decision not in {"approved", "changes_requested", "rejected"}:
        return _json_error("decision must be approved, changes_requested, or rejected.", 400)
    review.status = decision
    review.decision_note = _normalize_text(data.get("decision_note"), limit=10_000)
    review.decided_at = utc_now()
    review.updated_at = utc_now()
    case = _db().session.get(Case, review.case_id)
    case.review_status = "approved" if decision == "approved" else "rejected" if decision == "rejected" else "in_review"
    _collaboration_notification(
        review.requested_by_user_id, f"Review {decision.replace('_', ' ')}", case.case_number, "review"
    )
    _collaboration_audit(f"collaboration.review.{decision}", f"review:{review.id}", f"case:{case.id}")
    _db().session.commit()
    return jsonify(_review_json(review))


@api_v1_blueprint.get("/admin/investigations")
@require_role("admin")
def admin_investigations():  # type: ignore[no-untyped-def]
    """List every investigation with optional durable owner/reviewer filters."""
    statement = (
        select(Case)
        .where(
            Case.deleted_at.is_(None),
            Case.organization_id == _current_organization_id(),
        )
        .order_by(Case.opened_at.desc())
    )
    for argument, column in (("owner_user_id", Case.owner_user_id), ("reviewer_user_id", Case.reviewer_user_id)):
        value = request.args.get(argument)
        if value:
            try:
                statement = statement.where(column == _uuid(value, argument))
            except ValueError as error:
                return _json_error(str(error), 400)
    review_status = request.args.get("review_status")
    if review_status:
        statement = statement.where(Case.review_status == review_status)
    items = [_case_json(item, include_related=False) for item in _db().session.scalars(statement)]
    return jsonify(_page(items, total=len(items)))


@api_v1_blueprint.patch("/admin/investigations/<case_id>/review")
@require_role("admin")
def review_investigation(case_id: str):  # type: ignore[no-untyped-def]
    """Approve/reject an investigation, assign its reviewer, and retain review notes."""
    try:
        case = _db().session.get(Case, _uuid(case_id, "case_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if case is None or case.deleted_at is not None:
        return _json_error("Case was not found.", 404)
    data = request.get_json(silent=True) or {}
    decision = str(data.get("decision", case.review_status)).lower()
    if decision not in {"pending", "in_review", "approved", "rejected"}:
        return _json_error("decision must be pending, in_review, approved, or rejected.", 400)
    reviewer_id = data.get("reviewer_user_id")
    if reviewer_id is not None:
        try:
            reviewer = _db().session.get(User, _uuid(str(reviewer_id), "reviewer_user_id")) if reviewer_id else None
        except ValueError as error:
            return _json_error(str(error), 400)
        if reviewer_id and reviewer is None:
            return _json_error("Reviewer was not found.", 404)
        case.reviewer_user_id = reviewer.id if reviewer else None
    if "notes" in data:
        case.investigation_notes = _normalize_text(data.get("notes"), limit=20_000)
    case.review_status = decision
    case.updated_at = utc_now()
    _db().session.add(
        AuditLog(
            user_id=_current_user_id(),
            username=_current_username(),
            role="admin",
            action=f"investigation.review.{decision}",
            result="success",
            affected_object=case.case_number,
            reason=case.investigation_notes,
        )
    )
    _db().session.commit()
    return jsonify(_case_json(case, include_related=False))


@api_v1_blueprint.get("/notifications")
def list_notifications():  # type: ignore[no-untyped-def]
    session = _db().session
    q = _query_text()
    category = request.args.get("category", "all")
    include_archived = request.args.get("archived", "false").lower() in {"1", "true", "yes"}
    priority = request.args.get("priority", "all")
    statement = (
        select(Notification)
        .where(
            Notification.organization_id == _current_organization_id(),
            Notification.archived.is_(include_archived),
        )
        .order_by(Notification.pinned.desc(), Notification.created_at.desc())
        .limit(200)
    )
    if not _is_admin():
        statement = statement.where(Notification.owner_user_id == _current_user_id())
    owner = request.args.get("owner_user_id")
    if owner and _is_admin():
        try:
            statement = statement.where(Notification.owner_user_id == _uuid(owner, "owner_user_id"))
        except ValueError as error:
            return _json_error(str(error), 400)
    items = list(session.scalars(statement))
    if category != "all":
        items = [item for item in items if item.category == category]
    if q:
        items = [item for item in items if q in f"{item.title} {item.message}".lower()]
    if priority != "all":
        items = [item for item in items if item.priority == priority]
    payload = [_notification_json(item) for item in items]
    return jsonify({"unread_count": sum(1 for item in items if not item.read), "items": payload})


@api_v1_blueprint.get("/history")
def investigation_history():  # type: ignore[no-untyped-def]
    """Return one ownership-scoped projection of real notifications, activity, and security events."""
    session = _db().session
    user_id = _current_user_id()
    query_text = _query_text()
    case_id_text = request.args.get("case_id", "").strip()
    selected_case_id = None
    if case_id_text:
        try:
            selected_case_id = _uuid(case_id_text, "case_id")
        except ValueError as error:
            return _json_error(str(error), 400)
        if not _case_accessible(selected_case_id):
            return _forbidden()
    owned_case_ids = (
        {selected_case_id}
        if selected_case_id
        else set(session.scalars(select(Case.id).where(Case.deleted_at.is_(None))))
        if _is_admin()
        else _owned_case_ids()
    )
    timeline_statement = (
        select(TimelineEvent)
        .where(TimelineEvent.case_id.in_(owned_case_ids))
        .order_by(TimelineEvent.occurred_at.desc())
        .limit(300)
        if owned_case_ids
        else None
    )
    activity = (
        [_timeline_json(item) for item in session.scalars(timeline_statement)] if timeline_statement is not None else []
    )
    if query_text:
        activity = [
            item
            for item in activity
            if query_text in f"{item['event_type']} {item['summary']} {item.get('details') or ''}".lower()
        ]

    audit_rows = list(session.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(500)))
    if not _is_admin():
        owned_objects = {f"case:{item}" for item in owned_case_ids}
        evidence_ids = (
            set(session.scalars(select(Evidence.id).where(Evidence.case_id.in_(owned_case_ids))))
            if owned_case_ids
            else set()
        )
        report_ids = (
            set(session.scalars(select(Report.id).where(Report.case_id.in_(owned_case_ids))))
            if owned_case_ids
            else set()
        )
        timeline_ids = (
            set(session.scalars(select(TimelineEvent.id).where(TimelineEvent.case_id.in_(owned_case_ids))))
            if owned_case_ids
            else set()
        )
        owned_objects.update(f"evidence:{item}" for item in evidence_ids)
        owned_objects.update(f"report:{item}" for item in report_ids)
        owned_objects.update(f"timeline_event:{item}" for item in timeline_ids)
        audit_rows = [
            item
            for item in audit_rows
            if item.user_id == user_id or (item.affected_object and item.affected_object in owned_objects)
        ]
    result_filter = request.args.get("result", "all")
    action_filter = request.args.get("action", "all")
    if result_filter != "all":
        audit_rows = [item for item in audit_rows if item.result == result_filter]
    if action_filter != "all":
        audit_rows = [item for item in audit_rows if item.action.startswith(action_filter)]
    if query_text:
        audit_rows = [
            item for item in audit_rows if query_text in json.dumps(_audit_log_json(item), default=str).lower()
        ]

    notifications = list_notifications().get_json() or {"items": [], "unread_count": 0}
    if _is_admin():
        security_events = [
            _security_alert_json(item)
            for item in session.scalars(select(SecurityAlert).order_by(SecurityAlert.created_at.desc()).limit(200))
        ]
    else:
        security_events = [
            _audit_log_json(item)
            for item in audit_rows
            if item.action.startswith(("auth.", "rbac.", "csrf.", "rate_limit."))
        ]
    namespace = f"user:{user_id}"
    preferences = {}
    for item in session.scalars(select(Setting).where(Setting.namespace == namespace)):
        try:
            preferences[item.key] = json.loads(item.value)
        except (TypeError, json.JSONDecodeError):
            preferences[item.key] = item.value
    writer = current_app.extensions.get("cyberinvestigator_audit_writer")
    integrity = (
        writer.verify_integrity()
        if _is_admin() and writer is not None and hasattr(writer, "verify_integrity")
        else {"available": False, "reason": "Administrative access is required."}
    )
    critical = [item for item in notifications["items"] if item.get("priority") in {"critical", "high"}]
    return jsonify(
        {
            "critical_notifications": critical,
            "notifications": notifications,
            "investigation_activity": activity[:200],
            "audit_events": [_audit_log_json(item) for item in audit_rows[:200]],
            "security_events": security_events[:200],
            "preferences": preferences,
            "audit_integrity": integrity,
            "scope": {
                "case_ids": [str(item) for item in sorted(owned_case_ids, key=str)],
                "administrator": _is_admin(),
            },
        }
    )


@api_v1_blueprint.get("/account")
def account_workspace():  # type: ignore[no-untyped-def]
    """Return only the authenticated user's settings, sessions, history, and usage."""
    user_id = _current_user_id()
    if user_id is None:
        return _json_error("Authenticated user account was not found.", 401)
    session = _db().session
    account = session.get(User, user_id)
    if account is None:
        return _json_error("Authenticated user account was not found.", 404)
    sessions = list(
        session.scalars(
            select(UserSession)
            .where(UserSession.owner_user_id == user_id)
            .order_by(UserSession.created_at.desc())
            .limit(100)
        )
    )
    activity = list(
        session.scalars(
            select(AuditLog).where(AuditLog.user_id == user_id).order_by(AuditLog.created_at.desc()).limit(100)
        )
    )
    conversations = (
        session.scalar(select(func.count()).select_from(AIConversation).where(AIConversation.owner_user_id == user_id))
        or 0
    )
    exports = sum(1 for item in activity if "export" in item.action)
    namespace = f"user:{user_id}"
    preferences = {
        item.key: item.value for item in session.scalars(select(Setting).where(Setting.namespace == namespace))
    }
    return jsonify(
        {
            "profile": _user_json(account),
            "sessions": [
                {
                    "id": str(item.id),
                    "status": item.status,
                    "active": item.active,
                    "ip_address": item.ip_address,
                    "user_agent": item.user_agent,
                    "created_at": _iso(item.created_at),
                    "updated_at": _iso(item.updated_at),
                    "last_seen_at": _iso(item.last_seen_at),
                    "expires_at": _iso(item.expires_at),
                }
                for item in sessions
            ],
            "login_history": [_audit_log_json(item) for item in activity if item.action.startswith("auth.")],
            "recent_activity": [_audit_log_json(item) for item in activity],
            "api_usage": {"ai_conversations": conversations, "exports": exports, "requests_recorded": len(activity)},
            "preferences": preferences,
        }
    )


@api_v1_blueprint.patch("/account/preferences")
def update_account_preferences():  # type: ignore[no-untyped-def]
    user_id = _current_user_id()
    if user_id is None:
        return _json_error("Authenticated user account was not found.", 401)
    data = request.get_json(silent=True) or {}
    allowed = {"theme", "investigation_notifications", "security_notifications", "timezone", "locale"}
    for key, value in data.items():
        if key not in allowed:
            return _json_error(f"Unsupported preference: {key}.", 400)
        _set_setting(f"user:{user_id}", key, json.dumps(value), "json")
    _db().session.commit()
    _record_account_audit(
        "account.notification_preferences.updated",
        f"user:{user_id}",
        reason=f"Updated preference keys: {', '.join(sorted(data))}",
    )
    return account_workspace()


@api_v1_blueprint.delete("/account/sessions/<session_id>")
def revoke_account_session(session_id: str):  # type: ignore[no-untyped-def]
    try:
        record = _db().session.get(UserSession, _uuid(session_id, "session_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if record is None:
        return _json_error("Session was not found.", 404)
    if not _is_admin() and record.owner_user_id != _current_user_id():
        return _forbidden()
    record.active = False
    record.status = "revoked"
    record.updated_at = utc_now()
    _db().session.commit()
    _record_account_audit("account.session.revoked", f"session:{record.id}")
    return account_workspace()


@api_v1_blueprint.post("/notifications/read")
def mark_notifications_read():  # type: ignore[no-untyped-def]
    statement = select(Notification).where(
        Notification.organization_id == _current_organization_id(),
        Notification.read.is_(False),
    )
    if not _is_admin():
        statement = statement.where(Notification.owner_user_id == _current_user_id())
    changed = 0
    for item in _db().session.scalars(statement):
        item.read = True
        item.status = "read"
        changed += 1
    _db().session.commit()
    _record_account_audit("notifications.marked_read", f"user:{_current_user_id()}", reason=f"count:{changed}")
    return list_notifications()


@api_v1_blueprint.post("/notifications/<notification_id>/archive")
def archive_notification(notification_id: str):  # type: ignore[no-untyped-def]
    try:
        parsed_id = _uuid(notification_id, "notification_id")
    except ValueError as error:
        return _json_error(str(error), 400)
    item = _db().session.get(Notification, parsed_id)
    if item is None or item.organization_id != _current_organization_id():
        return _json_error("Notification was not found.", 404)
    if not _is_admin() and item.owner_user_id != _current_user_id():
        return _forbidden()
    item.archived = True
    item.status = "archived"
    _db().session.commit()
    _record_account_audit("notification.archived", f"notification:{item.id}")
    return list_notifications()


@api_v1_blueprint.post("/notifications/<notification_id>/read")
def mark_notification_read(notification_id: str):  # type: ignore[no-untyped-def]
    try:
        item = _db().session.get(Notification, _uuid(notification_id, "notification_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if item is None or item.organization_id != _current_organization_id():
        return _json_error("Notification was not found.", 404)
    if not _is_admin() and item.owner_user_id != _current_user_id():
        return _forbidden()
    item.read = True
    item.status = "read"
    _db().session.commit()
    _record_account_audit("notification.read", f"notification:{item.id}")
    return list_notifications()


@api_v1_blueprint.delete("/notifications/<notification_id>")
def delete_notification(notification_id: str):  # type: ignore[no-untyped-def]
    try:
        item = _db().session.get(Notification, _uuid(notification_id, "notification_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if item is None or item.organization_id != _current_organization_id():
        return _json_error("Notification was not found.", 404)
    if not _is_admin() and item.owner_user_id != _current_user_id():
        return _forbidden()
    notification_id_value = item.id
    _db().session.delete(item)
    _db().session.commit()
    _record_account_audit("notification.deleted", f"notification:{notification_id_value}")
    return list_notifications()


@api_v1_blueprint.get("/security/soc")
@require_role("admin")
def security_soc():  # type: ignore[no-untyped-def]
    return jsonify(_security_overview())


@api_v1_blueprint.get("/security/alerts")
@require_role("admin")
def security_alerts():  # type: ignore[no-untyped-def]
    session = _db().session
    return jsonify(
        {
            "items": [
                _security_alert_json(item)
                for item in session.scalars(select(SecurityAlert).order_by(SecurityAlert.created_at.desc()).limit(200))
            ]
        }
    )


@api_v1_blueprint.get("/security/report")
@require_role("admin")
def security_report():  # type: ignore[no-untyped-def]
    overview = _security_overview()
    document = {
        "executive_summary": f"Current security risk is {overview['risk_level']} with threat score {overview['threat_score']}/100.",
        "authentication_summary": overview["authentication"],
        "security_overview": overview,
        "threat_analysis": overview["ai_security_analyst"],
        "audit_logs": overview["recent_audit_logs"],
        "recommendations": overview["recommendations"],
        "risk_score": overview["threat_score"],
    }
    export_format = request.args.get("format", "json").lower()
    if export_format == "markdown":
        return Response(_report_markdown(document), mimetype="text/markdown")
    if export_format == "html":
        return Response(_report_html(document), mimetype="text/html")
    if export_format == "csv":
        return Response(_dicts_to_csv(document["audit_logs"]), mimetype="text/csv")
    return jsonify(document)


@api_v1_blueprint.get("/dashboard")
def dashboard_snapshot():  # type: ignore[no-untyped-def]
    """Return metrics for the dashboard widgets.

    Metrics are derived deterministically from persisted database state:
    - cases: count of non-deleted cases
    - evidence: count of evidence records within the newest case
    - timeline: count of timeline events within the newest case
    - plugin_status/ai_status: configuration/availability indicators
    - threat_score/progress: simple derived signals from timeline content

    This avoids synthetic values and does not duplicate UI logic.
    """

    cache_key = f"dashboard:{_current_user_role()}:{_current_username()}"
    cached = _runtime_cache().get(cache_key)
    if cached is not None:
        return jsonify(cached)

    db = _db()
    session = db.session

    case_scope = [
        Case.deleted_at.is_(None),
        Case.organization_id == _current_organization_id(),
    ]
    if not _is_admin():
        case_scope.append(Case.owner_user_id == _current_user_id())

    newest_case = session.scalar(select(Case).where(*case_scope).order_by(Case.opened_at.desc()).limit(1))
    active_cases = list(
        session.scalars(
            select(Case)
            .where(
                *case_scope,
                Case.archived_at.is_(None),
                Case.closed_at.is_(None),
            )
            .order_by(Case.opened_at.desc())
            .limit(8)
        )
    )
    recent_notifications = list_notifications().get_json()
    provider = _provider_status()
    plugin_registry = current_app.extensions.get("cyberinvestigator_plugin_registry")
    plugin_count = len(plugin_registry.list_metadata()) if _is_admin() and plugin_registry is not None else 0
    enabled_plugin_count = (
        session.scalar(select(func.count()).select_from(Plugin).where(Plugin.enabled.is_(True))) if _is_admin() else 0
    ) or 0
    plugin_execution_count = session.scalar(select(func.count()).select_from(PluginExecution)) if _is_admin() else 0
    plugin_failure_count = (
        session.scalar(
            select(func.count()).select_from(PluginExecution).where(PluginExecution.status.in_(["failed", "error"]))
        )
        if _is_admin()
        else 0
    ) or 0

    if newest_case is None:
        quick_actions = (
            [
                {
                    "label": "Security Center",
                    "description": "Review security posture and alerts.",
                    "href": "/admin#admin-security-pane",
                    "icon": "bi-shield-check",
                },
                {
                    "label": "Manage Users",
                    "description": "Review accounts, roles, and access.",
                    "href": "/admin#admin-users-pane",
                    "icon": "bi-people",
                },
                {
                    "label": "System Health",
                    "description": "Inspect platform readiness.",
                    "href": "/admin#admin-system-pane",
                    "icon": "bi-activity",
                },
            ]
            if _is_admin()
            else [
                {
                    "label": "New Investigation",
                    "description": "Start a new investigation workspace.",
                    "href": "/cases",
                    "icon": "bi-plus-lg",
                },
                {
                    "label": "Upload Evidence",
                    "description": "Register and analyze custody items.",
                    "href": "/evidence",
                    "icon": "bi-folder-plus",
                },
                {
                    "label": "AI Investigation",
                    "description": "Ask the assistant for triage guidance.",
                    "href": "/ai-chat",
                    "icon": "bi-stars",
                },
            ]
        )
        payload = {
            "cases_count": 0,
            "active_cases_count": 0,
            "active_cases": [],
            "selected_case_id": None,
            "selected_case": None,
            "evidence_count": 0,
            "timeline_count": 0,
            "reports_count": 0,
            "threat_score": None,
            "progress": None,
            "plugin_status": "enabled" if bool(current_app.config.get("PLUGINS_ENABLED", True)) else "disabled",
            "ai_status": bool(current_app.config["AI_ENABLED"]),
            "provider": provider,
            "recent_activity": [],
            "recent_evidence": [],
            "latest_reports": [],
            "ai_insights": [],
            "case_graph": [],
            "threat_graph": [],
            "timeline_preview": [],
            "plugin_health": {
                "configured": plugin_count,
                "enabled": enabled_plugin_count,
                "executions": plugin_execution_count,
                "failures": plugin_failure_count,
                "status": "disabled" if not bool(current_app.config.get("PLUGINS_ENABLED", True)) else "healthy",
            },
            "investigation_progress": {"completed": 0, "remaining": 10, "label": "No active case"},
            "lifecycle_progress": {
                "completed": 0,
                "total": 4,
                "stages": {"case": False, "evidence": False, "timeline": False, "report": False},
                "label": "No active case",
            },
            "quick_actions": quick_actions,
            "recent_notifications": recent_notifications.get("items", []) if recent_notifications else [],
        }
        _runtime_cache().set(
            cache_key,
            payload,
            ttl_seconds=int(current_app.config.get("DASHBOARD_CACHE_SECONDS", 5)),
        )
        return jsonify(payload)

    evidence_count = session.scalar(
        select(func.count())
        .select_from(Evidence)
        .where(Evidence.case_id == newest_case.id, Evidence.deleted_at.is_(None))
    )

    timeline_events = list(
        session.scalars(
            select(TimelineEvent)
            .where(TimelineEvent.case_id == newest_case.id)
            .order_by(TimelineEvent.occurred_at.desc())
            .limit(200)
        )
    )

    timeline_count = len(timeline_events)
    # Simple derived threat score: weighted by evidence acquisition + observations.
    # Keep it deterministic and cheap.
    threat = 0
    for ev in timeline_events:
        t = (ev.event_type or "").lower()
        if "evidence" in t:
            threat += 15
        if "observation" in t:
            threat += 10
        if "recommend" in t:
            threat += 8
        if "report" in t:
            threat += 12
    threat_score = min(100, threat)

    # Progress: ratio of timeline events (cap at 100% after 10 events)
    progress = min(100, int(round((timeline_count / 10) * 100)))
    all_case_count = session.scalar(select(func.count()).select_from(Case).where(*case_scope)) or 0
    report_scope = [Report.case_id == Case.id, *case_scope]
    reports_count = session.scalar(select(func.count()).select_from(Report, Case).where(*report_scope)) or 0
    recent_evidence = [
        _evidence_json(item)
        for item in session.scalars(
            select(Evidence)
            .where(Evidence.case_id == newest_case.id, Evidence.deleted_at.is_(None))
            .order_by(Evidence.acquired_at.desc())
            .limit(5)
        )
    ]
    latest_reports = [
        _report_json(item)
        for item in session.scalars(
            select(Report)
            .join(Case, Report.case_id == Case.id)
            .where(*case_scope)
            .order_by(Report.generated_at.desc())
            .limit(5)
        )
    ]
    recent_activity = [_timeline_json(item) for item in timeline_events[:6]]
    timeline_preview = [_timeline_json(item) for item in list(reversed(timeline_events[:6]))]
    event_type_counts: dict[str, int] = {}
    threat_graph = []
    running_threat = 0
    for event in reversed(timeline_events[:12]):
        event_type_counts[event.event_type] = event_type_counts.get(event.event_type, 0) + 1
        label = event.event_type.split(".")[0].replace("_", " ").title()
        delta = 15 if "evidence" in event.event_type.lower() else 12 if "report" in event.event_type.lower() else 10
        running_threat = min(100, running_threat + delta)
        threat_graph.append({"label": label, "value": running_threat, "occurred_at": _iso(event.occurred_at)})
    case_graph = [
        {
            "label": case.case_number,
            "value": session.scalar(
                select(func.count()).select_from(TimelineEvent).where(TimelineEvent.case_id == case.id)
            )
            or 0,
            "severity": case.severity,
        }
        for case in active_cases
    ]
    ai_records = list(
        session.scalars(
            select(AIReasoning)
            .where(AIReasoning.case_id == newest_case.id)
            .order_by(AIReasoning.created_at.desc())
            .limit(3)
        )
    )
    recommendations = list(
        session.scalars(
            select(Recommendation)
            .where(Recommendation.case_id == newest_case.id, Recommendation.status == "open")
            .order_by(Recommendation.created_at.desc())
            .limit(3)
        )
    )
    ai_insights = [
        {
            "title": f"{record.provider} / {record.model}",
            "body": _short_text(record.reasoning, "AI reasoning record available."),
            "created_at": _iso(record.created_at),
        }
        for record in ai_records
    ]
    ai_insights.extend(
        {
            "title": f"{item.priority.title()} priority recommendation",
            "body": _short_text(item.recommendation, "Open recommendation."),
            "created_at": _iso(item.created_at),
        }
        for item in recommendations
    )
    completed_stages = 1 + int(bool(evidence_count)) + int(bool(timeline_count)) + int(bool(reports_count))
    lifecycle_progress = completed_stages * 25

    quick_actions = (
        [
            {
                "label": "Manage Users",
                "description": "Review accounts, roles, and access.",
                "href": "/admin#admin-users-pane",
                "icon": "bi-people",
            },
            {
                "label": "Security Center",
                "description": "Open SOC posture and alerts.",
                "href": "/admin#admin-security-pane",
                "icon": "bi-shield-check",
            },
            {
                "label": "Plugin Manager",
                "description": "Validate and manage plugins.",
                "href": "/plugins",
                "icon": "bi-puzzle",
            },
            {
                "label": "OpenAI Status",
                "description": "Inspect provider readiness.",
                "href": "/admin#admin-openai-pane",
                "icon": "bi-stars",
            },
        ]
        if _is_admin()
        else [
            {
                "label": "New Investigation",
                "description": "Start a new investigation.",
                "href": "/cases",
                "icon": "bi-plus-lg",
            },
            {
                "label": "Upload Evidence",
                "description": "Add files and preserve custody.",
                "href": "/evidence",
                "icon": "bi-folder-plus",
            },
            {
                "label": "Generate Report",
                "description": "Prepare a report deliverable.",
                "href": "/reports",
                "icon": "bi-file-earmark-plus",
            },
            {
                "label": "Timeline",
                "description": "Review timeline threat signals.",
                "href": "/timeline",
                "icon": "bi-clock-history",
            },
            {
                "label": "AI Investigation",
                "description": "Ask contextual questions.",
                "href": "/ai-chat",
                "icon": "bi-stars",
            },
        ]
    )
    payload = {
        "cases_count": all_case_count,
        "active_cases_count": len(active_cases),
        "active_cases": [_case_json(case, include_related=False) for case in active_cases],
        "selected_case_id": str(newest_case.id),
        "selected_case": _case_json(newest_case),
        "evidence_count": evidence_count,
        "timeline_count": timeline_count,
        "reports_count": reports_count,
        "threat_score": threat_score,
        "progress": progress,
        "plugin_status": "enabled" if bool(current_app.config.get("PLUGINS_ENABLED", True)) else "disabled",
        "ai_status": bool(current_app.config["AI_ENABLED"]),
        "provider": provider,
        "recent_activity": recent_activity,
        "recent_evidence": recent_evidence,
        "latest_reports": latest_reports,
        "ai_insights": ai_insights[:4],
        "case_graph": case_graph,
        "threat_graph": threat_graph,
        "timeline_preview": timeline_preview,
        "event_type_counts": event_type_counts,
        "plugin_health": {
            "configured": plugin_count,
            "enabled": enabled_plugin_count,
            "executions": plugin_execution_count,
            "failures": plugin_failure_count,
            "status": "disabled"
            if not bool(current_app.config.get("PLUGINS_ENABLED", True))
            else "degraded"
            if plugin_failure_count
            else "healthy",
        },
        "investigation_progress": {
            "completed": timeline_count,
            "remaining": max(0, 10 - timeline_count),
            "label": f"{progress}% complete",
        },
        "lifecycle_progress": {
            "completed": completed_stages,
            "total": 4,
            "stages": {
                "case": True,
                "evidence": bool(evidence_count),
                "timeline": bool(timeline_count),
                "report": bool(reports_count),
            },
            "label": f"{lifecycle_progress}% lifecycle coverage",
        },
        "quick_actions": quick_actions,
        "recent_notifications": recent_notifications.get("items", []) if recent_notifications else [],
    }
    _runtime_cache().set(
        cache_key,
        payload,
        ttl_seconds=int(current_app.config.get("DASHBOARD_CACHE_SECONDS", 5)),
    )
    return jsonify(payload)
