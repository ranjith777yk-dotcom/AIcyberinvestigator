from __future__ import annotations

from sqlalchemy import select

from cyberinvestigator import create_app
from cyberinvestigator.infrastructure.database.models import AuditLog


def test_performance_workspace_reports_only_observed_or_unavailable_capacity() -> None:
    app = create_app("testing")
    client = app.test_client()

    denied = client.get("/api/v1/admin/performance", headers={"X-CI-Role": "user"})
    assert denied.status_code == 403

    response = client.get("/api/v1/admin/performance")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["platform_health"]["request_telemetry"]["requests_total"] >= 1
    assert payload["queue_status"]["provider"] == "in_process_thread_pool"
    assert payload["queue_status"]["durable"] is False
    assert payload["cache"]["shared_across_replicas"] is False
    assert payload["capacity"]["replica_count"] is None
    assert payload["high_availability"]["load_balancer"] == "unavailable"


def test_capacity_plan_and_cache_invalidation_are_audited() -> None:
    app = create_app("testing")
    client = app.test_client()
    client.get("/api/v1/dashboard")

    plan = client.patch(
        "/api/v1/admin/performance/capacity-plan",
        json={
            "target_p95_ms": 500,
            "maximum_queue_depth": 20,
            "minimum_free_storage_percent": 15,
            "reason": "Establish reviewed operational targets.",
        },
    )
    assert plan.status_code == 200

    invalidated = client.post(
        "/api/v1/admin/performance/cache/invalidate",
        json={"reason": "Refresh cached views after operations change."},
    )
    assert invalidated.status_code == 200
    assert invalidated.get_json()["scope"] == "current_process"

    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        actions = set(
            database.session.scalars(
                select(AuditLog.action).where(
                    AuditLog.action.in_(["performance.capacity_plan.updated", "performance.cache.invalidated"])
                )
            )
        )
        assert actions == {"performance.capacity_plan.updated", "performance.cache.invalidated"}


def test_performance_workspace_has_required_responsive_information_order() -> None:
    html = create_app("testing").test_client().get("/admin/performance").get_data(as_text=True)

    markers = ("Platform Health", "Capacity", "Queue Status", "Bottlenecks")
    positions = [html.index(marker) for marker in markers]
    assert positions == sorted(positions)
    assert "performance_workspace.css" in html
    assert "performance_workspace.js" in html
