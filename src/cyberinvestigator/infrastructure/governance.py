"""Governance evidence aggregation over existing policy, audit, and custody records."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from cyberinvestigator.infrastructure.database.models import AuditLog, Case, Evidence, SecurityAlert, Setting

CLASSIFICATION_LEVELS = ("public", "internal", "confidential", "restricted")
DEFAULT_GOVERNANCE_POLICY = {
    "version": 1,
    "classification_required": False,
    "default_classification": "internal",
    "retention_days": {
        "public": None,
        "internal": None,
        "confidential": None,
        "restricted": None,
    },
    "allowed_export_formats": {
        "public": ["json", "html", "md", "markdown", "csv", "xlsx", "excel", "docx", "pdf", "zip"],
        "internal": ["json", "html", "md", "markdown", "csv", "xlsx", "excel", "docx", "pdf", "zip"],
        "confidential": ["json", "pdf", "zip"],
        "restricted": ["pdf", "zip"],
    },
    "export_reason_required": False,
    "disposition_approval_required": True,
}


def decoded_setting(session, namespace: str, key: str, default):
    setting = session.scalar(select(Setting).where(Setting.namespace == namespace, Setting.key == key))
    if setting is None:
        return default, None, None
    try:
        value = json.loads(setting.value)
    except (TypeError, json.JSONDecodeError):
        return default, setting.updated_at, "invalid_json"
    return value, setting.updated_at, None


class GovernanceInspector:
    """Build a dashboard from persisted governance and operational evidence."""

    def snapshot(self, *, session, storage: dict[str, object]) -> dict[str, object]:
        policy, policy_updated, policy_error = decoded_setting(
            session, "governance", "policy", DEFAULT_GOVERNANCE_POLICY
        )
        classifications, _, classifications_error = decoded_setting(session, "governance", "classifications", {})
        holds, _, holds_error = decoded_setting(session, "storage", "legal_holds", {})
        privacy_requests, _, privacy_error = decoded_setting(session, "governance", "privacy_requests", [])
        disposition, _, disposition_error = decoded_setting(session, "governance", "disposition_reviews", [])
        valid_policy = isinstance(policy, dict) and policy_error is None
        effective_policy = policy if valid_policy else DEFAULT_GOVERNANCE_POLICY
        mapping = classifications if isinstance(classifications, dict) else {}
        hold_map = holds if isinstance(holds, dict) else {}
        alerts = list(
            session.scalars(
                select(SecurityAlert)
                .where(
                    SecurityAlert.status.in_(["open", "acknowledged"]),
                    SecurityAlert.category.in_(["governance", "privacy", "storage"]),
                )
                .order_by(SecurityAlert.created_at.desc())
                .limit(100)
            )
        )
        cases = list(session.scalars(select(Case).where(Case.deleted_at.is_(None)).order_by(Case.opened_at)))
        evidence_total = (
            session.scalar(select(func.count()).select_from(Evidence).where(Evidence.deleted_at.is_(None))) or 0
        )
        retention_alerts = self._retention_candidates(cases, mapping, hold_map, effective_policy)
        audits = list(
            session.scalars(
                select(AuditLog)
                .where(
                    AuditLog.action.contains("export")
                    | AuditLog.action.contains("legal_hold")
                    | AuditLog.action.contains("governance")
                    | AuditLog.action.contains("privacy")
                    | AuditLog.action.contains("disposition")
                )
                .order_by(AuditLog.created_at.desc())
                .limit(100)
            )
        )
        errors = [
            name
            for name, error in (
                ("policy", policy_error),
                ("classifications", classifications_error),
                ("legal_holds", holds_error),
                ("privacy_requests", privacy_error),
                ("disposition_reviews", disposition_error),
            )
            if error
        ]
        return {
            "collected_at": datetime.now(UTC).isoformat(),
            "critical_risks": [self._alert(item) for item in alerts if item.level in {"critical", "high"}],
            "policy_status": {
                "configured": policy_updated is not None and valid_policy,
                "valid": valid_policy,
                "updated_at": policy_updated.isoformat() if policy_updated else None,
                "effective_policy": effective_policy,
                "data_errors": errors,
            },
            "legal_holds": [
                item for item in hold_map.values() if isinstance(item, dict) and item.get("active") is True
            ],
            "retention_alerts": retention_alerts,
            "classification": {
                "levels": list(CLASSIFICATION_LEVELS),
                "classified_cases": sum(1 for case in cases if str(case.id) in mapping),
                "unclassified_cases": sum(1 for case in cases if str(case.id) not in mapping),
                "active_cases": len(cases),
                "assignments": [
                    {
                        "case_id": str(case.id),
                        "case_number": case.case_number,
                        "title": case.title,
                        "classification": self._classification(str(case.id), mapping, effective_policy),
                        "explicit": str(case.id) in mapping,
                    }
                    for case in cases
                ],
            },
            "privacy_requests": privacy_requests if isinstance(privacy_requests, list) else [],
            "disposition_reviews": disposition if isinstance(disposition, list) else [],
            "governance_activity": [self._audit(item) for item in audits],
            "metrics": {
                "active_cases": len(cases),
                "active_evidence": evidence_total,
                "active_legal_holds": sum(
                    1 for item in hold_map.values() if isinstance(item, dict) and item.get("active") is True
                ),
                "retention_candidates": len(retention_alerts),
                "governance_audit_events_returned": len(audits),
            },
            "storage": {
                "integrity": storage.get("integrity"),
                "policy": storage.get("policy"),
                "recovery": storage.get("recovery"),
            },
            "limitations": [
                "Retention alerts are review candidates; no automatic deletion is performed.",
                "Configured policy is not a certification of regulatory compliance.",
                "Secure physical erasure cannot be proven by this application on managed or copy-on-write storage.",
            ],
        }

    @staticmethod
    def _classification(case_id: str, mapping: dict, policy: dict) -> str:
        assignment = mapping.get(case_id)
        if isinstance(assignment, dict) and assignment.get("level") in CLASSIFICATION_LEVELS:
            return str(assignment["level"])
        return str(policy.get("default_classification") or "internal")

    def _retention_candidates(self, cases: list, mapping: dict, holds: dict, policy: dict) -> list[dict[str, object]]:
        retention = policy.get("retention_days") if isinstance(policy.get("retention_days"), dict) else {}
        now = datetime.now(UTC)
        candidates = []
        for case in cases:
            level = self._classification(str(case.id), mapping, policy)
            days = retention.get(level)
            if not isinstance(days, int) or days <= 0:
                continue
            opened_at = case.opened_at
            if opened_at.tzinfo is None:
                opened_at = opened_at.replace(tzinfo=UTC)
            review_at = opened_at + timedelta(days=days)
            if review_at > now:
                continue
            hold = holds.get(str(case.id))
            candidates.append(
                {
                    "case_id": str(case.id),
                    "case_number": case.case_number,
                    "classification": level,
                    "review_due_at": review_at.isoformat(),
                    "legal_hold": bool(isinstance(hold, dict) and hold.get("active") is True),
                    "status": "blocked_by_legal_hold"
                    if isinstance(hold, dict) and hold.get("active") is True
                    else "review_required",
                }
            )
        return candidates

    @staticmethod
    def _alert(item) -> dict[str, object]:
        return {
            "id": str(item.id),
            "level": item.level,
            "category": item.category,
            "title": item.title,
            "message": item.message,
            "status": item.status,
            "created_at": item.created_at.isoformat(),
        }

    @staticmethod
    def _audit(item) -> dict[str, object]:
        return {
            "id": str(item.id),
            "action": item.action,
            "result": item.result,
            "username": item.username,
            "affected_object": item.affected_object,
            "reason": item.reason,
            "created_at": item.created_at.isoformat(),
        }
