from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from cyberinvestigator import create_app
from cyberinvestigator.infrastructure.database.migrations import DEFAULT_ORGANIZATION_ID
from cyberinvestigator.infrastructure.database.models import AuditLog, DetectionAlert, TimelineEvent

ADMIN = {"X-CI-User": "investigator", "X-CI-Role": "admin"}


def _case_evidence_and_hunt(client):
    case = client.post(
        "/api/v1/cases",
        headers=ADMIN,
        json={"case_number": "HUNT-1", "title": "Proactive hunt"},
    ).get_json()
    evidence = client.post(
        "/api/v1/evidence",
        headers=ADMIN,
        json={
            "case_id": case["id"],
            "evidence_number": "HUNT-E-1",
            "filename": "observations.txt",
            "content": "Observed network request https://example.test/path",
        },
    ).get_json()
    assert client.get(f"/api/v1/evidence/{evidence['id']}/analysis", headers=ADMIN).status_code == 200
    hunt = client.post(
        "/api/v1/threat-hunting/hunts",
        headers=ADMIN,
        json={
            "case_id": case["id"],
            "name": "Observed URL review",
            "hypothesis": "Determine whether the recorded URL appears elsewhere in preserved evidence.",
            "scope": "Current investigation evidence only.",
        },
    ).get_json()
    return case, evidence, hunt


def test_hunt_lifecycle_ioc_correlation_sigma_rule_alert_and_audit() -> None:
    app = create_app("testing", {"MULTI_TENANT_ENABLED": True})
    client = app.test_client()
    case, evidence, hunt = _case_evidence_and_hunt(client)

    active = client.patch(
        f"/api/v1/threat-hunting/hunts/{hunt['id']}",
        headers=ADMIN,
        json={"status": "active"},
    )
    assert active.status_code == 200
    assert active.get_json()["started_at"] is not None
    search = client.post(
        f"/api/v1/threat-hunting/hunts/{hunt['id']}/ioc-searches",
        headers=ADMIN,
        json={"indicator_type": "url", "indicator_value": "https://example.test/path", "enrich": True},
    )
    assert search.status_code == 200
    assert search.get_json()["evidence_matches"] == 1
    assert search.get_json()["provider_status"] == "unavailable"
    assert search.get_json()["provider_findings"] == 0
    assert search.get_json()["correlations"][0]["evidence_id"] == evidence["id"]

    rule = client.post(
        "/api/v1/detection-rules",
        headers=ADMIN,
        json={
            "rule_key": "observed-url",
            "enabled": True,
            "definition": {
                "title": "Observed URL indicator",
                "logsource": {"category": "threat_hunting"},
                "detection": {
                    "selection": {"indicator": [{"type": "url", "value": "https://example.test/path"}]},
                    "condition": "selection",
                },
                "tags": ["attack.t1071.001"],
            },
        },
    )
    assert rule.status_code == 201
    evaluated = client.post(
        f"/api/v1/detection-rules/{rule.get_json()['id']}/evaluate",
        headers=ADMIN,
        json={"hunt_id": hunt["id"]},
    )
    assert evaluated.status_code == 200
    assert evaluated.get_json()["match_count"] == 1
    assert evaluated.get_json()["execution_semantics"] == "indicator_match_v1"

    workspace = client.get("/api/v1/threat-hunting", headers=ADMIN).get_json()
    assert workspace["active_hunts"][0]["status"] == "active"
    assert workspace["attack_coverage"] == ["T1071.001"]
    assert workspace["detection_alerts"][0]["source"] == "verified_evidence"
    assert workspace["provider_status"]["available"] is False
    suggestions = client.post(
        f"/api/v1/threat-hunting/hunts/{hunt['id']}/ai-recommendations",
        headers=ADMIN,
        json={},
    ).get_json()
    assert suggestions["provenance"] == "ai_generated_suggestion"
    assert suggestions["verified_finding"] is False

    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        alert = database.session.scalar(select(DetectionAlert))
        assert str(alert.evidence_id) == evidence["id"]
        actions = set(
            database.session.scalars(
                select(AuditLog.action).where(
                    AuditLog.organization_id == DEFAULT_ORGANIZATION_ID,
                    AuditLog.action.in_(
                        [
                            "threat_hunt.created",
                            "threat_hunt.updated",
                            "threat_hunt.ioc_searched",
                            "detection_rule.created",
                            "detection_rule.evaluated",
                            "threat_hunt.ai_recommendations.requested",
                        ]
                    ),
                )
            )
        )
        assert len(actions) == 6
        timeline_types = set(
            database.session.scalars(select(TimelineEvent.event_type).where(TimelineEvent.case_id == UUID(case["id"])))
        )
        assert {"threat_hunt.active", "detection_rule.matched"} <= timeline_types


def test_unsupported_sigma_semantics_are_not_treated_as_detections() -> None:
    app = create_app("testing")
    client = app.test_client()
    _case, _evidence, hunt = _case_evidence_and_hunt(client)
    rule = client.post(
        "/api/v1/detection-rules",
        headers=ADMIN,
        json={
            "rule_key": "unsupported-rule",
            "enabled": True,
            "definition": {
                "title": "Unsupported aggregation",
                "logsource": {"category": "process_creation"},
                "detection": {"selection": {"Image": "example.exe"}, "condition": "1 of selection*"},
                "tags": [],
            },
        },
    ).get_json()
    response = client.post(
        f"/api/v1/detection-rules/{rule['id']}/evaluate",
        headers=ADMIN,
        json={"hunt_id": hunt["id"]},
    )
    assert response.status_code == 409
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        assert database.session.scalar(select(DetectionAlert)) is None


def test_hunt_and_rule_records_are_isolated_by_active_organization() -> None:
    app = create_app("testing", {"MULTI_TENANT_ENABLED": True})
    client = app.test_client()
    _case, _evidence, hunt = _case_evidence_and_hunt(client)
    organization = client.post(
        "/api/v1/organizations",
        headers=ADMIN,
        json={"name": "Hunt Tenant", "slug": "hunt-tenant", "reason": "Isolation test."},
    ).get_json()
    second = {**ADMIN, "X-CI-Organization": organization["id"]}
    assert (
        client.patch(
            f"/api/v1/threat-hunting/hunts/{hunt['id']}",
            headers=second,
            json={"status": "active"},
        ).status_code
        == 404
    )
    assert client.get("/api/v1/threat-hunting", headers=second).get_json()["hunt_history"] == []


def test_threat_hunting_mobile_information_order() -> None:
    html = create_app("testing").test_client().get("/threat-hunting").get_data(as_text=True)
    labels = ("Active Hunts", "IOC Search", "Detection Alerts", "ATT&amp;CK Coverage")
    assert [html.index(label) for label in labels] == sorted(html.index(label) for label in labels)
    assert "threat_hunting.css" in html
    assert 'aria-live="polite"' in html
