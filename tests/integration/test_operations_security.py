"""Integration coverage for production security and operations endpoints."""

from cyberinvestigator import create_app


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
