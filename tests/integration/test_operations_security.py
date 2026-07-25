"""Integration coverage for production security and operations endpoints."""

from sqlalchemy import select

from cyberinvestigator import create_app
from cyberinvestigator.infrastructure.database.models import AuditLog, SecurityAlert


def _headers(username: str, role: str = "user") -> dict[str, str]:
    return {"X-CI-User": username, "X-CI-Role": role}


def test_health_and_metrics_endpoints_are_available() -> None:
    client = create_app("testing").test_client()

    assert client.get("/api/v1/health/live").status_code == 200
    ready = client.get("/api/v1/health/ready")
    assert ready.status_code == 200
    assert ready.get_json()["database"] == "ok"
    metrics = client.get("/api/v1/monitoring/metrics")
    assert metrics.status_code == 200
    assert "cases" in metrics.get_json()


def test_admin_endpoints_redact_secret_values() -> None:
    client = create_app("testing", {"AI_API_KEY": "secret-test-key"}).test_client()

    response = client.get("/api/v1/admin/secrets")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["configured"]["ai_api_key"] is True
    assert payload["values_exposed"] is False
    assert "secret-test-key" not in response.get_data(as_text=True)


def test_rbac_blocks_non_admin_for_admin_endpoint() -> None:
    client = create_app("testing").test_client()

    response = client.get("/api/v1/admin/users", headers={"X-CI-Role": "viewer"})

    assert response.status_code == 403


def test_security_headers_include_request_id() -> None:
    client = create_app("testing").test_client()

    response = client.get("/api/v1/health/live", headers={"X-Request-ID": "test-request"})

    assert response.headers["X-Request-ID"] == "test-request"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_operations_center_reports_only_observed_or_explicitly_unavailable_data() -> None:
    app = create_app("testing")
    response = app.test_client().get("/api/v1/admin/operations", headers=_headers("operator", "admin"))

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "operational"
    assert payload["health"]["database"] == "ok"
    assert set(payload["metrics"]["jobs"]) == {"queued", "running", "completed", "failed"}
    assert payload["resource_usage"]["memory"]["status"] == "unavailable"
    assert payload["resource_usage"]["cpu"]["status"] == "unavailable"
    assert payload["resource_usage"]["storage"]["status"] == "available"
    assert payload["resource_usage"]["storage"]["total_bytes"] > 0
    assert "threat_score" not in payload
    assert "risk_level" not in payload


def test_admin_can_manage_alert_lifecycle_with_audit_trace() -> None:
    app = create_app("testing")
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        alert = SecurityAlert(
            level="critical",
            category="operations",
            title="Observed service failure",
            message="A configured service reported an error.",
            status="open",
            score=90,
            confidence=100,
        )
        database.session.add(alert)
        database.session.commit()
        alert_id = str(alert.id)

    response = app.test_client().patch(
        f"/api/v1/admin/alerts/{alert_id}",
        headers=_headers("operator", "admin"),
        json={"status": "acknowledged"},
    )

    assert response.status_code == 200
    assert response.get_json()["status"] == "acknowledged"
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        audit = database.session.scalar(select(AuditLog).where(AuditLog.action == "admin.security_alert.acknowledged"))
        assert audit is not None
        assert audit.affected_object == f"security_alert:{alert_id}"


def test_maintenance_mode_blocks_users_but_keeps_admin_and_health_accessible() -> None:
    app = create_app("testing")
    client = app.test_client()
    admin_headers = _headers("operator", "admin")

    enabled = client.patch(
        "/api/v1/admin/maintenance",
        headers=admin_headers,
        json={"enabled": True, "message": "Scheduled evidence-store maintenance."},
    )
    assert enabled.status_code == 200
    assert enabled.get_json()["enabled"] is True

    blocked = client.get("/api/v1/cases", headers=_headers("investigator"))
    assert blocked.status_code == 503
    assert blocked.get_json()["error"] == "platform maintenance"
    assert client.get("/api/v1/admin/operations", headers=admin_headers).status_code == 200
    assert client.get("/api/v1/health/live").status_code == 200

    disabled = client.patch(
        "/api/v1/admin/maintenance",
        headers=admin_headers,
        json={"enabled": False, "message": "Maintenance complete."},
    )
    assert disabled.status_code == 200
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        actions = set(
            database.session.scalars(select(AuditLog.action).where(AuditLog.action.like("admin.maintenance.%")))
        )
        assert actions == {"admin.maintenance.enabled", "admin.maintenance.disabled"}
