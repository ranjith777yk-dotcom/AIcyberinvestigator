"""Integration coverage for truthful operational telemetry and trace correlation."""

from __future__ import annotations

import json
import logging

from cyberinvestigator import create_app


def _admin_headers(**extra: str) -> dict[str, str]:
    return {"X-CI-User": "operator", "X-CI-Role": "admin", **extra}


def test_observability_workspace_reports_measured_process_telemetry(tmp_path) -> None:
    app = create_app("testing", {"LOGS_FOLDER": tmp_path / "logs", "OBSERVABILITY_MAX_TRACES": 25})
    client = app.test_client()

    client.get("/api/v1/health/live")
    response = client.get("/api/v1/admin/observability", headers=_admin_headers())

    assert response.status_code == 200
    payload = response.get_json()
    telemetry = payload["telemetry"]
    assert telemetry["requests_total"] >= 1
    assert telemetry["latency_ms"]["sample_count"] >= 1
    assert telemetry["retention"]["scope"] == "current_process"
    assert telemetry["retention"]["max_traces"] == 25
    assert payload["traces"]
    assert payload["services"][0]["source"] == "readiness probe"
    assert (
        next(item for item in payload["sources"] if item["name"] == "Distributed trace exporter")["status"]
        == "unavailable"
    )


def test_traceparent_is_correlated_and_server_timing_is_measured() -> None:
    app = create_app("testing")
    client = app.test_client()
    trace_id = "1" * 32
    parent_span_id = "2" * 16

    response = client.get(
        "/api/v1/health/live",
        headers={"traceparent": f"00-{trace_id}-{parent_span_id}-01"},
    )

    assert response.status_code == 200
    assert response.headers["traceparent"].startswith(f"00-{trace_id}-")
    assert response.headers["Server-Timing"].startswith("app;dur=")
    traces = app.extensions["cyberinvestigator_telemetry"].recent_traces()
    assert traces[0]["trace_id"] == trace_id
    assert traces[0]["parent_span_id"] == parent_span_id


def test_invalid_correlation_headers_and_unmatched_routes_are_bounded() -> None:
    app = create_app("testing")
    client = app.test_client()

    response = client.get(
        "/not-a-real-route/credential-like-value",
        headers={"traceparent": f"00-{'0' * 32}-{'0' * 16}-01", "X-Request-ID": "invalid id with spaces"},
    )

    assert response.status_code == 404
    assert response.headers["X-Request-ID"] != "invalid id with spaces"
    assert f"00-{'0' * 32}-" not in response.headers["traceparent"]
    telemetry = app.extensions["cyberinvestigator_telemetry"]
    trace = telemetry.recent_traces()[0]
    assert trace["path"] == "<unmatched>"
    assert "GET <unmatched>" in telemetry.snapshot()["top_routes"]


def test_structured_logs_redact_credentials_before_persistence_and_display(tmp_path) -> None:
    log_directory = tmp_path / "logs"
    app = create_app("testing", {"LOGS_FOLDER": log_directory, "AI_API_KEY": "configured-bare-secret"})
    app.logger.warning("password=super-secret token=abc123 provider configured-bare-secret")
    logging.getLogger("cyberinvestigator.worker").warning("api_key=worker-secret")

    response = app.test_client().get("/api/v1/admin/observability", headers=_admin_headers())

    assert response.status_code == 200
    rendered = response.get_data(as_text=True)
    assert "super-secret" not in rendered
    assert "abc123" not in rendered
    assert "configured-bare-secret" not in rendered
    assert "worker-secret" not in rendered
    assert "[REDACTED]" in rendered
    persisted = (log_directory / "cyberinvestigator.log").read_text(encoding="utf-8").splitlines()
    events = [json.loads(line) for line in persisted]
    assert events[-2]["message"] == "password=[REDACTED] token=[REDACTED] provider [REDACTED]"
    assert events[-1]["message"] == "api_key=[REDACTED]"


def test_observability_workspace_enforces_admin_rbac() -> None:
    response = (
        create_app("testing")
        .test_client()
        .get(
            "/api/v1/admin/observability",
            headers={"X-CI-User": "analyst", "X-CI-Role": "user"},
        )
    )

    assert response.status_code == 403
