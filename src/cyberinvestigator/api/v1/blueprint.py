"""Version 1 API blueprint."""

from __future__ import annotations

import csv
import html
import json
import shutil
import time
import zipfile
from io import BytesIO, StringIO
from pathlib import Path
from uuid import UUID

from flask import Blueprint, Response, current_app, g, jsonify, request, stream_with_context
from sqlalchemy import func, select, text

from cyberinvestigator.api.v1.openapi import build_openapi_spec
from cyberinvestigator.application.dto import CaseCreateRequest, CaseUpdateRequest, EvidenceAddRequest
from cyberinvestigator.application.ports.ai_provider import AIRequest
from cyberinvestigator.application.services import CaseManagementService, EvidenceService
from cyberinvestigator.application.services.timeline_service import TimelineService
from cyberinvestigator.domain.services.forensic_analyzer import ForensicAnalyzer
from cyberinvestigator.infrastructure.ai import AIProviderUnavailable, build_ai_registry
from cyberinvestigator.infrastructure.ai import messages as ai_messages
from cyberinvestigator.infrastructure.database.base import utc_now
from cyberinvestigator.infrastructure.database.models import (
    AIReasoning,
    AuditLog,
    Case,
    Evidence,
    Notification,
    Plugin,
    PluginExecution,
    Recommendation,
    Report,
    Role,
    SecurityAlert,
    Setting,
    TimelineEvent,
    User,
    UserSession,
)
from cyberinvestigator.infrastructure.evidence_storage import LocalEvidenceStorage
from cyberinvestigator.infrastructure.plugins.loader import PluginLoadError
from cyberinvestigator.infrastructure.plugins.registry import PluginMetadata
from cyberinvestigator.infrastructure.repositories import SQLAlchemyCaseRepository, SQLAlchemyEvidenceRepository
from cyberinvestigator.infrastructure.repositories.timeline_repository import SQLAlchemyTimelineRepository
from cyberinvestigator.infrastructure.security.web_security import hash_password, require_role
from cyberinvestigator.shared.exceptions import (
    CaseManagementError,
    EvidenceManagementError,
)

api_v1_blueprint = Blueprint("api_v1", __name__, url_prefix="/api/v1")
"""Blueprint namespace for stable version 1 API endpoints."""


def _db():
    return current_app.extensions["cyberinvestigator_database"]


def _case_service() -> CaseManagementService:
    return CaseManagementService(SQLAlchemyCaseRepository(_db().session), current_app.logger)


def _evidence_service() -> EvidenceService:
    session = _db().session
    storage = LocalEvidenceStorage(Path(current_app.config["UPLOAD_FOLDER"]))
    return EvidenceService(
        SQLAlchemyCaseRepository(session),
        SQLAlchemyEvidenceRepository(session),
        storage,
        current_app.logger,
    )


def _timeline_service() -> TimelineService:
    return TimelineService(SQLAlchemyTimelineRepository(_db().session), current_app.logger)


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


def _case_json(case):
    case_id = case.id
    attachments = []
    history = []
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
        "tags": _json_list(getattr(case, "tags", None)),
        "notes": _json_list(getattr(case, "notes", None)),
        "relationships": _json_list(getattr(case, "relationships", None)),
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
    case = _db().session.get(Case, event.case_id)
    evidence = _db().session.get(Evidence, event.evidence_id) if event.evidence_id else None
    event_type = event.event_type or ""
    threat_weight = (
        15 if "evidence" in event_type else 12 if "report" in event_type else 10 if "observation" in event_type else 6
    )
    return {
        "id": str(event.id),
        "case_id": str(event.case_id),
        "case_number": case.case_number if case else None,
        "evidence_id": str(event.evidence_id) if event.evidence_id else None,
        "evidence_number": evidence.evidence_number if evidence else None,
        "artifact_id": str(event.artifact_id) if event.artifact_id else None,
        "occurred_at": _iso(event.occurred_at),
        "event_type": event_type,
        "group": event_type.split(".", 1)[0] if "." in event_type else event_type,
        "threat_weight": threat_weight,
        "threat_level": "high" if threat_weight >= 15 else "medium" if threat_weight >= 10 else "low",
        "summary": event.summary,
        "details": event.details,
    }


def _report_json(report):
    return {
        "id": str(report.id),
        "case_id": str(report.case_id),
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
    return set(
        _db().session.scalars(
            select(Case.id).where(
                Case.deleted_at.is_(None),
                func.lower(Case.owner) == _current_username().lower(),
            )
        )
    )


def _case_accessible(case_id: UUID) -> bool:
    if _is_admin():
        return True
    case = _db().session.get(Case, case_id)
    return bool(case and (case.owner or "").lower() == _current_username().lower())


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
    if "owner" in data:
        case.owner = _normalize_text(data.get("owner"), limit=255)
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
    current_app.extensions.pop("cyberinvestigator_dashboard_cache", None)


def _ai_runtime():
    return (
        current_app.extensions.get("cyberinvestigator_ai_registry"),
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
    test_live_ai_disabled = bool(current_app.config.get("TESTING")) and not bool(current_app.config.get("AI_ENABLED"))
    return {
        "provider": status.provider,
        "available": bool(status.available and not test_live_ai_disabled),
        "configured": status.configured,
        "model": status.model,
        "message": status.message,
        "endpoint": status.endpoint,
        "installed_models": list(status.installed_models),
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
        }
        for name, status in statuses.items()
    }


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
        "Do not invent facts; clearly mark uncertainty and recommend verification steps."
    )
    if route == "investigation":
        return (
            base
            + " Use the supplied current case, evidence, timeline, reports, threat score, conversation history, and uploads only as needed."
        )
    if route == "cybersecurity":
        return base + " Answer the cybersecurity question directly without assuming a specific case unless the user asks."
    return base + " Treat this as normal conversation. Do not force an investigation summary or mention case context unless asked."


def _chat_user_payload(user_message: str, context: dict[str, object], history: list[dict[str, object]], route: str) -> str:
    clean_history = [
        {"role": str(item.get("role", ""))[:20], "content": str(item.get("content", ""))[:2000]}
        for item in history[-12:]
        if isinstance(item, dict)
    ]
    if route == "general":
        return json.dumps({"message": user_message, "history": clean_history}, default=str)
    if route == "cybersecurity":
        return json.dumps({"question": user_message, "history": clean_history}, default=str)
    scoped = {
        "case_id": context.get("case_id"),
        "case_number": context.get("case_number"),
        "title": context.get("title"),
        "evidence": context.get("evidence", []),
        "timeline": context.get("timeline", []),
        "reports": context.get("reports", []),
        "threat_score": context.get("threat_score"),
        "uploaded_evidence": context.get("uploaded_evidence", []),
    }
    return json.dumps({"request": user_message, "history": clean_history, "context": scoped}, default=str)


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
    status = _provider_status()
    selected_provider = str(current_app.config.get("AI_PROVIDER", "ollama"))
    selected_model = str(current_app.config.get("AI_MODEL") or status.get("model") or "qwen3:8b")
    route = _chat_route(user_message, uploads)
    safe_message = user_message.replace("\r", " ").replace("\n", " ")[:500]
    print(
        "[AI DEBUG] Incoming User Message="
        f"{safe_message!r} route={route} selected_provider={selected_provider} selected_model={selected_model}"
    )
    ai_disabled = not bool(current_app.config.get("AI_ENABLED", True))
    test_live_ai_disabled = bool(current_app.config.get("TESTING")) and not bool(current_app.config.get("AI_ENABLED"))
    if registry is None or ai_disabled or test_live_ai_disabled:
        print(
            "[AI DEBUG] provider_call=False "
            f"provider={selected_provider} model={selected_model} response_id=n/a "
            "input_tokens=n/a output_tokens=n/a latency_ms=0 finish_reason=not_configured_or_disabled"
        )
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
        actual_model = str(getattr(provider, "model", None) or selected_model)
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
        latency_ms = round((time.perf_counter() - started_at) * 1000, 2) if "started_at" in locals() else "n/a"
        current_app.logger.warning("AI chat provider failed: %s", error)
        print(
            "[AI DEBUG] provider_call=True "
            f"provider={selected_provider} model={selected_model} response_id=n/a "
            f"input_tokens=n/a output_tokens=n/a latency_ms={latency_ms} finish_reason=error"
        )
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
        latency_ms = round((time.perf_counter() - started_at) * 1000, 2) if "started_at" in locals() else "n/a"
        current_app.logger.warning("AI chat provider failed: %s", error)
        print(
            "[AI DEBUG] provider_call=True "
            f"provider={selected_provider} model={selected_model} response_id=n/a "
            f"input_tokens=n/a output_tokens=n/a latency_ms={latency_ms} finish_reason=error"
        )
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


def _tail_file(path: Path, *, lines: int = 80) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:]
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
            "provider": {**status, "available": False, "message": "AI provider enrichment failed. Local fallback was used."},
            "content": "AI enrichment is temporarily unavailable. Local deterministic analysis is available.",
        }


def _local_report_analysis(document: dict[str, object], context: dict[str, object]) -> str:
    registry, _, analysis_engine = _ai_runtime()
    _ = registry
    evidence = context.get("evidence", []) if isinstance(context.get("evidence"), list) else []
    timeline = context.get("timeline", []) if isinstance(context.get("timeline"), list) else []
    reports = context.get("reports", []) if isinstance(context.get("reports"), list) else []
    text = json.dumps({"report": document, "context": context}, default=str)
    analysis = analysis_engine.analyze_text(text) if analysis_engine is not None else None
    threat_score = analysis.threat_score if analysis is not None else document.get("threat_score", 0)
    iocs = analysis.iocs if analysis is not None else {}
    mitre = analysis.mitre_attack if analysis is not None else []
    recommendations = (
        analysis.recommendations if analysis is not None else ["Review evidence, timeline, and report gaps."]
    )
    ioc_count = sum(len(values) for values in iocs.values()) if isinstance(iocs, dict) else 0
    mitre_lines = (
        "\n".join(
            f"- {item.get('technique_id', 'Unknown')}: {item.get('technique', 'Technique')}" for item in mitre[:8]
        )
        if mitre
        else "- No confident MITRE mapping was detected from the available local context."
    )
    recommendation_lines = "\n".join(f"- {item}" for item in recommendations[:8])
    return (
        "## Executive Summary\n"
        f"This report was reviewed with {len(evidence)} evidence item(s), {len(timeline)} timeline event(s), "
        f"and {len(reports)} related report record(s). Local analysis found {ioc_count} IOC candidate(s).\n\n"
        "## Threat Assessment\n"
        f"Risk score: **{threat_score}/100**. Validate the highest-risk evidence and timeline events before release.\n\n"
        "## MITRE Mapping\n"
        f"{mitre_lines}\n\n"
        "## IOC Analysis\n"
        f"{ioc_count} candidate indicator(s) were extracted from report and investigation context.\n\n"
        "## Recommendations\n"
        f"{recommendation_lines}\n\n"
        "## Confidence\n"
        "Medium when local analysis is used; high-confidence conclusions require live AI enrichment and analyst review.\n\n"
        "## Evidence Quality\n"
        "Confirm hashes, custody timestamps, acquisition source, and analysis completeness for every evidence item.\n\n"
        "## Missing Information\n"
        "Document business impact, affected assets, containment status, and any unresolved timeline gaps."
    )


def _investigation_context(case_id: str | None = None) -> dict[str, object]:
    session = _db().session
    parsed_case_id = None
    if case_id:
        try:
            parsed_case_id = _uuid(case_id, "case_id")
        except ValueError:
            parsed_case_id = None
    context_scope = [Case.deleted_at.is_(None)]
    if not _is_admin():
        context_scope.append(func.lower(Case.owner) == _current_username().lower())
    case = (
        session.get(Case, parsed_case_id)
        if parsed_case_id
        else session.scalar(select(Case).where(*context_scope).order_by(Case.opened_at.desc()).limit(1))
    )
    if case is None or not _case_accessible(case.id):
        return {
            "case_id": None,
            "case_number": None,
            "case": None,
            "evidence": [],
            "timeline": [],
            "reports": [],
            "plugins": [],
        }
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
    return {
        "case_id": str(case.id),
        "case_number": case.case_number,
        "case": _case_json(case),
        "evidence": evidence,
        "timeline": timeline,
        "reports": reports,
        "plugins": plugins,
    }


def _build_report_document(case_id: UUID, report_type: str, ai_summary: dict[str, object]) -> dict[str, object]:
    context = _investigation_context(str(case_id))
    evidence = context["evidence"]
    timeline = context["timeline"]
    threat_score = min(
        100,
        sum(
            15 if "evidence" in item["event_type"] else 12 if "report" in item["event_type"] else 10
            for item in timeline
        ),
    )
    iocs: list[str] = []
    mitre = []
    for item in evidence:
        report = item.get("analysis_report") or {}
        root = report.get("root", {}) if isinstance(report, dict) else {}
        for flag in root.get("flags", []) if isinstance(root, dict) else []:
            iocs.append(str(flag))
        for finding in report.get("findings", []) if isinstance(report, dict) else []:
            detail = str(finding.get("detail", ""))
            if detail and detail not in iocs:
                iocs.append(detail)
    if any("credential" in str(item).lower() or "phish" in str(item).lower() for item in timeline):
        mitre.append({"technique_id": "T1566", "technique_name": "Phishing", "tactic": "Initial Access"})
    if any("archive" in str(item).lower() or "compression" in str(item).lower() for item in evidence):
        mitre.append(
            {"technique_id": "T1027", "technique_name": "Obfuscated Files or Information", "tactic": "Defense Evasion"}
        )
    if not mitre:
        mitre.append(
            {"technique_id": "Triage", "technique_name": "No direct ATT&CK mapping detected", "tactic": "Analysis"}
        )
    recommendations = [
        "Preserve original evidence and verify SHA-256 before every transfer.",
        "Review timeline gaps and correlate suspicious events with source evidence.",
        "Escalate high-entropy, embedded-content, or flag-bearing artifacts for deeper manual review.",
    ]
    charts = {
        "threat_score": threat_score,
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
        "executive_summary": f"{context['case_number']} contains {len(evidence)} evidence item(s), {len(timeline)} timeline event(s), and a threat score of {threat_score}/100.",
        "investigation_summary": context,
        "evidence": evidence,
        "timeline": timeline,
        "threat_score": threat_score,
        "iocs": iocs[:50],
        "mitre_attack": mitre,
        "ai_explanation": ai_summary,
        "recommendations": recommendations,
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
        ("Investigation Summary", "investigation_summary"),
        ("Evidence", "evidence"),
        ("Timeline", "timeline"),
        ("Threat Score", "threat_score"),
        ("IOCs", "iocs"),
        ("MITRE ATT&CK", "mitre_attack"),
        ("AI Explanation", "ai_explanation"),
        ("Recommendations", "recommendations"),
        ("Appendix", "appendix"),
        ("Charts", "charts"),
    ):
        lines.extend([f"## {title}", ""])
        value = document[key]
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
        ("Investigation Summary", "investigation_summary"),
        ("Evidence", "evidence"),
        ("Timeline", "timeline"),
        ("Threat Score", "threat_score"),
        ("IOCs", "iocs"),
        ("MITRE ATT&CK", "mitre_attack"),
        ("AI Explanation", "ai_explanation"),
        ("Recommendations", "recommendations"),
        ("Appendix", "appendix"),
        ("Charts", "charts"),
    ):
        value = document[key]
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
        evidence = _db().session.get(Evidence, _uuid(str(evidence_id), "evidence_id"))
    except ValueError as error:
        return _json_error(str(error), 400)
    if evidence is None or evidence.deleted_at is not None:
        return _json_error("Evidence was not found.", 404)
    path = Path(current_app.config["UPLOAD_FOLDER"]) / evidence.storage_path
    try:
        result = ForensicAnalyzer().analyze_path(
            path,
            evidence_number=evidence.evidence_number,
            original_filename=evidence.original_filename,
            sha256=evidence.sha256,
        )
    except OSError as error:
        return _json_error(f"Evidence file could not be read: {error}", 400)
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
    payload["ai_explanation"] = _ai_completion(
        "Explain forensic evidence findings, encoding, compression, archive contents, hidden strings, flags, metadata, entropy, and next steps.",
        payload,
    )
    return jsonify(payload)


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
    return jsonify(
        {
            "provider": status.provider,
            "available": status.available,
            "configured": status.configured,
            "model": status.model,
            "message": status.message,
            "endpoint": status.endpoint,
            "installed_models": list(status.installed_models),
        }
    )


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
        return jsonify({"available": False, "reply": response, "message": response, "analysis": {}})

    history = document.get("history", [])
    if not isinstance(history, list):
        history = []
    context = _investigation_context(str(document.get("case_id") or "") or None)
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
        }
    )


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
            context = _investigation_context(str(document.get("case_id") or "") or None)
            if uploads:
                context["uploaded_evidence"] = uploads
                context["evidence"] = _investigation_context(str(context.get("case_id") or "") or None).get(
                    "evidence", context.get("evidence", [])
                )
            registry, assistant, _ = _ai_runtime()
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
            yield _sse(
                {
                    "type": "done",
                    "available": bool(status.get("available")),
                    "provider_status": status,
                    "uploads": uploads or [],
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
                "dependencies": [
                    {
                        "name": dep.name,
                        "version_specifier": dep.version_specifier,
                        "required": dep.required,
                    }
                    for dep in metadata.dependencies
                ],
                "status": lifecycle_status,
                "marketplace_ready": bool(metadata.description and metadata.version and metadata.capabilities),
                "validation": "valid",
                "versioning": {"current": metadata.version, "identifier": metadata.identifier},
            }
        )

    return jsonify({"enabled": enabled, "count": len(plugins), "plugins": plugins})


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
    destination.mkdir(parents=True, exist_ok=True)
    if safe_name.lower().endswith(".zip"):
        try:
            with zipfile.ZipFile(BytesIO(upload.read())) as archive:
                for member in archive.infolist():
                    target = (destination / member.filename).resolve()
                    if not str(target).startswith(str(destination)):
                        return _json_error("Plugin archive contains an unsafe path.", 400)
                archive.extractall(destination)
        except zipfile.BadZipFile:
            return _json_error("Plugin archive is not a valid ZIP file.", 400)
    else:
        upload.save(destination / safe_name)
    try:
        response = reload_plugins()
    except PluginLoadError as error:
        return _json_error(f"Plugin uploaded but validation failed: {error}", 400)
    inventory = response.get_json()
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
        elif action == "delete":
            record = loader._get_loaded(plugin_id)
            plugin_dir = record.manifest.module_file.parent.resolve()
            loader.unload(plugin_id)
            plugin_root = Path(current_app.config["PLUGINS_FOLDER"]).resolve()
            if plugin_dir.exists() and str(plugin_dir).startswith(str(plugin_root)):
                shutil.rmtree(plugin_dir)
        else:
            return _json_error("Unsupported plugin action.", 404)
    except (KeyError, PluginLoadError, OSError) as error:
        return _json_error(str(error), 400)
    return plugin_inventory()


@api_v1_blueprint.get("/cases")
def list_cases():  # type: ignore[no-untyped-def]
    cases = [_case_json(case) for case in _case_service().list_cases(include_archived=True)]
    if not _is_admin():
        username = _current_username().lower()
        cases = [case for case in cases if (case.get("owner") or "").lower() == username]
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
        _invalidate_dashboard_cache()
        return jsonify(_case_json(case_record)), 201
    except (ValueError, CaseManagementError) as error:
        return _json_error(str(error), 400)


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
            case = service.close_case(parsed)
        elif action == "archive":
            case = service.archive_case(parsed)
        elif action == "delete":
            case = service.delete_case(parsed)
        else:
            return _json_error("Unsupported case action.", 404)
        _invalidate_dashboard_cache()
        return jsonify(_case_json(case))
    except (ValueError, CaseManagementError) as error:
        return _json_error(str(error), 400)


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
        _invalidate_dashboard_cache()
        return jsonify(_evidence_json(created)), 201
    except (ValueError, CaseManagementError, EvidenceManagementError) as error:
        return _json_error(str(error), 400)


@api_v1_blueprint.delete("/evidence/<evidence_id>")
def delete_evidence(evidence_id: str):  # type: ignore[no-untyped-def]
    try:
        evidence = _db().session.get(Evidence, _uuid(evidence_id, "evidence_id"))
        if evidence is None or not _case_accessible(evidence.case_id):
            return _forbidden()
        deleted = _evidence_service().delete_evidence(_uuid(evidence_id, "evidence_id"))
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


@api_v1_blueprint.get("/evidence/export")
def export_evidence():  # type: ignore[no-untyped-def]
    response = list_evidence()
    data = response.get_json()
    output = StringIO()
    output.write("id,case_id,evidence_number,filename,media_type,size_bytes,sha256,acquired_at\n")
    for item in data["items"]:
        output.write(
            f"{item['id']},{item['case_id']},{item['evidence_number']},{item['original_filename']},"
            f"{item['media_type'] or ''},{item['size_bytes']},{item['sha256']},{item['acquired_at']}\n"
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
                    "correlations": {"cases": [], "evidence": [], "groups": {}, "threat_score": 0},
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
    payload["correlations"] = {
        "cases": sorted({item["case_number"] for item in items if item["case_number"]}),
        "evidence": sorted({item["evidence_number"] for item in items if item["evidence_number"]}),
        "groups": {
            name: sum(1 for item in items if item["group"] == name)
            for name in sorted({item["group"] for item in items})
        },
        "threat_score": min(100, sum(int(item["threat_weight"]) for item in items)),
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
    context = _investigation_context(str(data.get("case_id") or "") or None)
    if context.get("case_id") and not _case_accessible(_uuid(str(context["case_id"]), "case_id")):
        return _forbidden()
    return jsonify(
        _ai_completion(
            "Summarize this investigation timeline with case, evidence, threat, gaps, and recommended next actions.",
            context,
        )
    )


@api_v1_blueprint.post("/timeline")
def create_timeline_event():  # type: ignore[no-untyped-def]
    data = request.get_json(silent=True) or {}
    try:
        parsed_case_id = _uuid(str(data.get("case_id", "")), "case_id")
        if not _case_accessible(parsed_case_id):
            return _forbidden()
        event = _timeline_service().record_investigation_event(
            case_id=parsed_case_id,
            event_type=str(data.get("event_type", "observation.manual")),
            summary=str(data.get("summary", "")),
            details=data.get("details"),
        )
        _invalidate_dashboard_cache()
        return jsonify(_timeline_json(event)), 201
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
            report_type=report_type,
            version=version,
            title=str(data.get("title") or f"{case.case_number} {report_type.title()} Report v{version}"),
            storage_path=storage_path,
        )
        session.add(report)
        session.commit()
        report_file = Path(current_app.config["REPORTS_FOLDER"]) / storage_path
        context = _investigation_context(str(case_id))
        ai_summary = _ai_completion(
            "Create an investigation report narrative with executive summary, investigation summary, evidence, timeline, threat score, IOCs, MITRE ATT&CK, recommendations, appendix, and charts.",
            context,
            max_tokens=1200,
        )
        document = _build_report_document(case_id, report_type, ai_summary)
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
        _invalidate_dashboard_cache()
        return jsonify(_report_json(report)), 201
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
        "Analyze this investigation report and its case context. Return Markdown with Executive Summary, Threat "
        "Assessment, MITRE Mapping, IOC Analysis, Risk Score, Recommendations, Confidence, Evidence Quality, and "
        "Missing Information.",
        source,
        max_tokens=1400,
    )
    if not analysis.get("available"):
        analysis["content"] = _local_report_analysis(document, context)
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
    base_name = f"{report.report_type}-v{report.version}"
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
        endpoint = str(value).strip().rstrip("/")
        if not endpoint.startswith(("http://", "https://")):
            raise ValueError("Ollama endpoint must start with http:// or https://.")
        current_app.config["OLLAMA_ENDPOINT"] = endpoint
    else:
        return
    current_app.extensions["cyberinvestigator_ai_registry"] = build_ai_registry(current_app.config)


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
    return jsonify(
        {
            "cases": session.scalar(select(func.count()).select_from(Case)),
            "evidence": session.scalar(select(func.count()).select_from(Evidence)),
            "timeline_events": session.scalar(select(func.count()).select_from(TimelineEvent)),
            "reports": session.scalar(select(func.count()).select_from(Report)),
            "plugins_loaded": current_app.extensions.get("cyberinvestigator_plugin_loaded_count", 0),
            "rate_limit_requests": current_app.config.get("RATE_LIMIT_REQUESTS"),
        }
    )


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
    jobs = [
        {"name": "dashboard_cache", "status": "idle", "schedule": "on demand"},
        {
            "name": "plugin_discovery",
            "status": "ready" if current_app.config.get("PLUGINS_ENABLED") else "disabled",
            "schedule": "manual",
        },
        {"name": "evidence_analysis", "status": "ready", "schedule": "on demand"},
        {"name": "backup", "status": "manual", "schedule": "scripted"},
    ]
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
            "background_jobs": jobs,
            "plugin_health": plugins,
            "ai_status": _provider_status(),
            "openai_status": _provider_status(),
            "security": _security_overview(),
        }
    )


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
    if role_name not in {"admin", "user"}:
        return _json_error("role must be admin or user.", 400)
    if not username or not email or len(password) < 10:
        return _json_error("username, email, and a password of at least 10 characters are required.", 400)
    session = _db().session
    role = session.scalar(select(Role).where(Role.name == role_name))
    if role is None:
        return _json_error("role was not found.", 404)
    if session.scalar(
        select(User).where((func.lower(User.username) == username.lower()) | (func.lower(User.email) == email.lower()))
    ):
        return _json_error("user already exists.", 409)
    user = User(username=username, email=email, password_hash=hash_password(password), role_id=role.id, status="active")
    session.add(user)
    session.add(
        AuditLog(
            username=getattr(getattr(request, "user", None), "username", None),
            action="admin.user.create",
            result="success",
            affected_object=username,
        )
    )
    session.commit()
    return jsonify({"user": _user_json(user)}), 201


@api_v1_blueprint.patch("/admin/users/<user_id>")
@require_role("admin")
def update_user(user_id: str):  # type: ignore[no-untyped-def]
    data = request.get_json(silent=True) or {}
    session = _db().session
    user = session.get(User, _uuid(user_id))
    if user is None:
        return _json_error("user was not found.", 404)
    if "status" in data:
        status = str(data["status"])
        if status not in {"active", "disabled", "suspended"}:
            return _json_error("status must be active, disabled, or suspended.", 400)
        user.status = status
    if "role" in data:
        role_name = str(data["role"]).strip().lower()
        if role_name == "administrator":
            role_name = "admin"
        if role_name not in {"admin", "user"}:
            return _json_error("role must be admin or user.", 400)
        role = session.scalar(select(Role).where(Role.name == role_name))
        if role is None:
            return _json_error("role was not found.", 404)
        user.role_id = role.id
    if "password" in data and str(data["password"]):
        if len(str(data["password"])) < 10:
            return _json_error("password must contain at least 10 characters.", 400)
        user.password_hash = hash_password(str(data["password"]))
    session.add(
        AuditLog(
            username=user.username,
            role=user.role.name,
            action="admin.user.update",
            result="success",
            affected_object=user.username,
        )
    )
    session.commit()
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


@api_v1_blueprint.get("/notifications")
def list_notifications():  # type: ignore[no-untyped-def]
    session = _db().session
    q = _query_text()
    category = request.args.get("category", "all")
    items = list(
        session.scalars(
            select(Notification)
            .where(Notification.archived.is_(False))
            .where(
                True
                if _is_admin()
                else (
                    (Notification.user_id.is_(None) & Notification.category.not_in(["security", "database", "plugins"]))
                    | (Notification.user_id == _current_user_id())
                )
            )
            .order_by(Notification.pinned.desc(), Notification.created_at.desc())
            .limit(200)
        )
    )
    if category != "all":
        items = [item for item in items if item.category == category]
    if q:
        items = [item for item in items if q in f"{item.title} {item.message}".lower()]
    payload = [
        {
            "id": str(item.id),
            "title": item.title,
            "message": item.message,
            "category": item.category,
            "priority": item.priority,
            "read": item.read,
            "pinned": item.pinned,
            "created_at": _iso(item.created_at),
        }
        for item in items
    ]
    return jsonify({"unread_count": sum(1 for item in items if not item.read), "items": payload})


@api_v1_blueprint.post("/notifications/read")
def mark_notifications_read():  # type: ignore[no-untyped-def]
    statement = select(Notification).where(Notification.read.is_(False))
    if not _is_admin():
        statement = statement.where(Notification.user_id == _current_user_id())
    for item in _db().session.scalars(statement):
        item.read = True
    _db().session.commit()
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
    if not _is_admin() and item.user_id not in {None, _current_user_id()}:
        return _forbidden()
    item.archived = True
    _db().session.commit()
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
        case_scope.append(func.lower(Case.owner) == _current_username().lower())

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
    if not ai_insights:
        ai_insights.append(
            {
                "title": "Local analysis ready",
                "body": provider["message"],
                "created_at": None,
            }
        )

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
        "quick_actions": quick_actions,
        "recent_notifications": recent_notifications.get("items", []) if recent_notifications else [],
    }
    current_app.extensions[cache_key] = {"created_at": now, "payload": payload}
    return jsonify(payload)
