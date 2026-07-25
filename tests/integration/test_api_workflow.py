from __future__ import annotations

from sqlalchemy import select

from cyberinvestigator import create_app
from cyberinvestigator.infrastructure.database.models import AuditLog


def test_operational_api_workflow_connects_modules() -> None:
    app = create_app("testing")
    client = app.test_client()

    case_response = client.post(
        "/api/v1/cases",
        json={
            "case_number": "CASE-API-1",
            "title": "API Workflow",
            "description": "Integrated workflow smoke test",
            "severity": "high",
        },
    )
    assert case_response.status_code == 201
    case_id = case_response.get_json()["id"]

    evidence_response = client.post(
        "/api/v1/evidence",
        json={
            "case_id": case_id,
            "evidence_number": "EV-API-1",
            "filename": "artifact.txt",
            "content": "suspicious event",
            "media_type": "text/plain",
            "source_description": "Collected during workflow test",
        },
    )
    assert evidence_response.status_code == 201

    timeline_response = client.post(
        "/api/v1/timeline",
        json={
            "case_id": case_id,
            "summary": "Manual analyst observation",
            "details": "Observation is linked to the same case.",
        },
    )
    assert timeline_response.status_code == 201
    timeline_event_id = timeline_response.get_json()["id"]
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        audit = database.session.scalar(
            select(AuditLog).where(
                AuditLog.action == "timeline.manual_event.created",
                AuditLog.affected_object == f"timeline_event:{timeline_event_id}",
            )
        )
        assert audit is not None

    report_response = client.post(
        "/api/v1/reports",
        json={"case_id": case_id, "report_type": "technical", "title": "Technical Report"},
    )
    assert report_response.status_code == 201

    dashboard = client.get("/api/v1/dashboard").get_json()
    assert dashboard["cases_count"] == 1
    assert dashboard["evidence_count"] == 1
    assert dashboard["timeline_count"] >= 4
    assert dashboard["threat_score"] > 0

    assert client.get("/api/v1/cases?q=workflow").get_json()["pagination"]["total"] == 1
    assert client.get(f"/api/v1/evidence?case_id={case_id}").get_json()["pagination"]["total"] == 1
    timeline_payload = client.get(f"/api/v1/timeline?case_id={case_id}").get_json()
    assert timeline_payload["pagination"]["total"] >= 4
    assert timeline_payload["reconstruction"]["summary"]["confirmed_events"] >= 4
    assert timeline_payload["reconstruction"]["summary"]["hypotheses"] == 0
    assert all(item["certainty"] == "confirmed" for item in timeline_payload["items"])
    assert client.get(f"/api/v1/reports?case_id={case_id}").get_json()["pagination"]["total"] == 1

    settings_response = client.patch(
        "/api/v1/settings",
        json={"namespace": "workspace", "settings": {"theme": "dark"}},
    )
    assert settings_response.status_code == 200
    assert client.post("/api/v1/notifications/read").get_json()["unread_count"] == 0
    assert client.get("/api/v1/openapi.json").status_code == 200
