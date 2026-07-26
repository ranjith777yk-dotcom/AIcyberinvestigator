from __future__ import annotations

from sqlalchemy import select

from cyberinvestigator import create_app
from cyberinvestigator.infrastructure.database.models import AuditLog


def _create_case(client, number: str = "GOV-001") -> str:
    response = client.post(
        "/api/v1/cases",
        json={"case_number": number, "title": "Governed Investigation", "severity": "medium"},
    )
    assert response.status_code == 201
    return response.get_json()["id"]


def _policy(**overrides):
    document = {
        "default_classification": "internal",
        "classification_required": False,
        "export_reason_required": False,
        "disposition_approval_required": True,
        "retention_days": {"public": None, "internal": None, "confidential": 365, "restricted": 730},
        "allowed_export_formats": {
            "public": ["json", "pdf"],
            "internal": ["json", "pdf"],
            "confidential": ["json", "pdf", "zip"],
            "restricted": ["pdf", "zip"],
        },
        "reason": "Establish investigation governance controls.",
    }
    document.update(overrides)
    return document


def test_governance_workspace_is_admin_only_and_uses_persisted_evidence() -> None:
    app = create_app("testing")
    client = app.test_client()
    case_id = _create_case(client)

    denied = client.get("/api/v1/admin/governance", headers={"X-CI-Role": "user"})
    assert denied.status_code == 403

    classified = client.put(
        f"/api/v1/admin/governance/classifications/{case_id}",
        json={"level": "confidential", "reason": "Contains sensitive investigation records."},
    )
    assert classified.status_code == 200

    workspace = client.get("/api/v1/admin/governance")
    assert workspace.status_code == 200
    payload = workspace.get_json()
    assert payload["classification"]["classified_cases"] == 1
    assert payload["classification"]["assignments"][0]["classification"] == "confidential"
    assert payload["critical_risks"] == []
    assert payload["limitations"]
    report = client.get("/api/v1/admin/governance/report?format=csv")
    assert report.status_code == 200
    assert report.mimetype == "text/csv"
    assert b"retention_candidates" in report.data


def test_policy_privacy_and_disposition_changes_are_audited() -> None:
    app = create_app("testing")
    client = app.test_client()
    case_id = _create_case(client, "GOV-002")

    assert client.put("/api/v1/admin/governance/policy", json=_policy()).status_code == 200
    privacy = client.post(
        "/api/v1/admin/governance/privacy-requests",
        json={
            "request_type": "access",
            "subject_reference": "subject-ref-001",
            "reason": "Record an authorized data access review.",
        },
    )
    assert privacy.status_code == 201
    assert privacy.get_json()["automated_action_taken"] is False

    disposition = client.post(
        "/api/v1/admin/governance/disposition-reviews",
        json={"case_id": case_id, "reason": "Retention review reached its approved review date."},
    )
    assert disposition.status_code == 201
    assert disposition.get_json()["deletion_executed"] is False
    assert disposition.get_json()["secure_erasure_verified"] is False

    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        actions = set(
            database.session.scalars(
                select(AuditLog.action).where(
                    AuditLog.action.in_(
                        [
                            "governance.policy.updated",
                            "privacy.request.created",
                            "governance.disposition.requested",
                        ]
                    )
                )
            )
        )
        assert actions == {
            "governance.policy.updated",
            "privacy.request.created",
            "governance.disposition.requested",
        }


def test_legal_hold_blocks_disposition_review() -> None:
    client = create_app("testing").test_client()
    case_id = _create_case(client, "GOV-003")
    hold = client.patch(
        f"/api/v1/admin/storage/legal-holds/{case_id}",
        json={"active": True, "reason": "Preserve records for an active proceeding."},
    )
    assert hold.status_code == 200

    blocked = client.post(
        "/api/v1/admin/governance/disposition-reviews",
        json={"case_id": case_id, "reason": "Requested retention disposition review."},
    )
    assert blocked.status_code == 409
    assert "legal hold" in blocked.get_json()["error"].lower()


def test_restricted_classification_governs_report_export() -> None:
    client = create_app("testing").test_client()
    case_id = _create_case(client, "GOV-004")
    report = client.post(
        "/api/v1/reports",
        json={"case_id": case_id, "report_type": "technical", "title": "Governed Report"},
    )
    assert report.status_code == 201
    report_id = report.get_json()["id"]
    assert client.put("/api/v1/admin/governance/policy", json=_policy(classification_required=True)).status_code == 200

    unclassified = client.get(f"/api/v1/reports/{report_id}/export?format=json")
    assert unclassified.status_code == 409

    assert (
        client.put(
            f"/api/v1/admin/governance/classifications/{case_id}",
            json={"level": "restricted", "reason": "Highly sensitive investigation material."},
        ).status_code
        == 200
    )
    forbidden = client.get(f"/api/v1/reports/{report_id}/export?format=json")
    assert forbidden.status_code == 403
    allowed = client.get(f"/api/v1/reports/{report_id}/export?format=pdf")
    assert allowed.status_code == 200
    assert allowed.mimetype == "application/pdf"


def test_governance_workspace_mobile_information_order() -> None:
    html = create_app("testing").test_client().get("/admin/governance").get_data(as_text=True)

    markers = ("Critical Risks", "Policy Status", "Legal Holds", "Retention Alerts")
    assert [html.index(marker) for marker in markers] == sorted(html.index(marker) for marker in markers)
    assert "governance_workspace.css" in html
    assert "governance_workspace.js" in html
