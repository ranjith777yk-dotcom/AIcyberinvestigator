"""Version 1 API blueprint."""

from __future__ import annotations

import csv
import hashlib
import html
import json
import re
import shutil
import stat
import time
import tomllib
import zipfile
from io import BytesIO, StringIO
from pathlib import Path
from urllib.parse import urlparse
from uuid import UUID, uuid4

from flask import Blueprint, Response, current_app, g, has_request_context, jsonify, request, stream_with_context
from sqlalchemy import func, select, text

from cyberinvestigator.api.v1.openapi import build_openapi_spec
from cyberinvestigator.application.dto import CaseCreateRequest, CaseUpdateRequest, EvidenceAddRequest
from cyberinvestigator.application.ports.ai_provider import AIRequest
from cyberinvestigator.application.ports.threat_intelligence import normalize_indicator
from cyberinvestigator.domain.services.forensic_analyzer import ForensicAnalyzer
from cyberinvestigator.infrastructure.ai import AIProviderUnavailable, build_ai_registry
from cyberinvestigator.infrastructure.ai import messages as ai_messages
from cyberinvestigator.infrastructure.ai_management import hydrate_ai_config
from cyberinvestigator.infrastructure.database.base import utc_now
from cyberinvestigator.infrastructure.database.models import (
    AIConversation,
    AIReasoning,
    AuditLog,
    Case,
    Evidence,
    Notification,
    Permission,
    Plugin,
    PluginExecution,
    Recommendation,
    Report,
    Role,
    RolePermission,
    SecurityAlert,
    Setting,
    TimelineEvent,
    Upload,
    User,
    UserSession,
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


def _db():
    return current_app.extensions["cyberinvestigator_database"]


def _features():
    return current_app.extensions["cyberinvestigator_features"]


def _storage_manager():
    return current_app.extensions["cyberinvestigator_storage_manager"]


def _deployment_inspector():
    return current_app.extensions["cyberinvestigator_deployment_inspector"]


def _case_service():
    return _features().cases.service(_db().session, current_app.logger)


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


def _is_admin() -> bool:
    return _current_user_role() == "admin"


def _owned_case_ids() -> set[UUID]:
    if _is_admin():
        return set()
    user_id = _current_user_id()
    if user_id is None:
        return set()
    return set(_db().session.scalars(select(Case.id).where(Case.deleted_at.is_(None), Case.owner_user_id == user_id)))


def _case_accessible(case_id: UUID) -> bool:
    if _is_admin():
        return True
    case = _db().session.get(Case, case_id)
    return bool(case and _current_user_id() is not None and case.owner_user_id == _current_user_id())


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

    _db().session.add(
        AuditLog(
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
        .where(AIConversation.conversation_id == thread_id, AIConversation.owner_user_id == _current_user_id())
        .limit(1)
    )
    title = existing.title if existing else (user_message.strip()[:80] or "New chat")
    record = AIConversation(
        owner_user_id=_current_user_id(),
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
    for key in list(current_app.extensions):
        if key.startswith(("cyberinvestigator_dashboard_cache", "cyberinvestigator_context_cache")):
            current_app.extensions.pop(key, None)


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
    cache_key = (
        f"cyberinvestigator_context_cache:{_current_user_role()}:{_current_user_id()}:{parsed_case_id or 'latest'}"
    )
    cached = current_app.extensions.get(cache_key)
    if cached and time.time() - cached["created_at"] < 10:
        return json.loads(json.dumps(cached["payload"]))
    context_scope = [Case.deleted_at.is_(None)]
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
        current_app.extensions[cache_key] = {"created_at": time.time(), "payload": empty}
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
    current_app.extensions[cache_key] = {"created_at": time.time(), "payload": payload}
    return json.loads(json.dumps(payload))


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
        "iocs": iocs[:50],
        "mitre_attack": mitre,
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
    _update_analysis_job(job_id, 16, "Reading custody file")
    path = _features().evidence.resolve_path(evidence.storage_path)
    try:
        result = ForensicAnalyzer().analyze_path(
            path,
            evidence_number=evidence.evidence_number,
            original_filename=evidence.original_filename,
            sha256=evidence.sha256,
            progress=lambda value, step: _update_analysis_job(job_id, value, step),
        )
    except OSError as error:
        raise FileNotFoundError(str(error)) from error
    _update_analysis_job(job_id, 72, "Saving forensic findings")
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
    evidence.analysis_report = json.dumps(result.report, default=str, indent=2)
    _db().session.commit()
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
    return jsonify(build_openapi_spec(current_app))


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
    statement = select(AIConversation).order_by(AIConversation.created_at.desc())
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
    statement = select(AIConversation).where(AIConversation.conversation_id == parsed)
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
    statement = select(Case).where(Case.deleted_at.is_(None)).order_by(Case.opened_at.desc())
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
        created = _case_service().create_case(
            CaseCreateRequest(
                case_number=str(data.get("case_number", "")),
                title=str(data.get("title", "")),
                description=data.get("description"),
                severity=str(data.get("severity", "medium")),
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
    if not _is_admin():
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
    if not _is_admin():
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
    if not _is_admin():
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
    base_name = f"{report.report_type}-v{report.version}"
    _record_report_audit(report, "report.exported", reason=f"format:{export_format} · version:{report.version}")
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
            "cases": session.scalar(select(func.count()).select_from(Case)),
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
    return jsonify(payload)


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
            "cases": session.scalar(select(func.count()).select_from(Case)),
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
                    "cases": session.scalar(select(func.count()).select_from(Case)) or 0,
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
                "cases": session.scalar(select(func.count()).select_from(Case)),
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


@api_v1_blueprint.get("/admin/investigations")
@require_role("admin")
def admin_investigations():  # type: ignore[no-untyped-def]
    """List every investigation with optional durable owner/reviewer filters."""
    statement = select(Case).where(Case.deleted_at.is_(None)).order_by(Case.opened_at.desc())
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
        .where(Notification.archived.is_(include_archived))
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
    payload = [
        {
            "id": str(item.id),
            "title": item.title,
            "message": item.message,
            "category": item.category,
            "priority": item.priority,
            "read": item.read,
            "pinned": item.pinned,
            "archived": item.archived,
            "status": item.status,
            "owner_user_id": str(item.owner_user_id) if item.owner_user_id else None,
            "created_by": str(item.created_by_user_id) if item.created_by_user_id else None,
            "created_at": _iso(item.created_at),
            "updated_at": _iso(item.updated_at),
        }
        for item in items
    ]
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
    statement = select(Notification).where(Notification.read.is_(False))
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
    if item is None:
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
    if item is None:
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
    if item is None:
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

    cache_key = f"cyberinvestigator_dashboard_cache:{_current_user_role()}:{_current_username()}"
    cached = current_app.extensions.get(cache_key)
    now = time.time()
    if cached and now - cached["created_at"] < int(current_app.config.get("DASHBOARD_CACHE_SECONDS", 5)):
        return jsonify(cached["payload"])

    db = _db()
    session = db.session

    case_scope = [Case.deleted_at.is_(None)]
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
        current_app.extensions[cache_key] = {"created_at": now, "payload": payload}
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
    current_app.extensions[cache_key] = {"created_at": now, "payload": payload}
    return jsonify(payload)
