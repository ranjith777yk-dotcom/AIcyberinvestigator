"""Integration coverage for truthful deployment state, verification, and rollback planning."""

from __future__ import annotations

import json

from sqlalchemy import select

from cyberinvestigator import create_app
from cyberinvestigator.infrastructure.database.models import AuditLog, Setting


def _app(tmp_path, **overrides):
    project = tmp_path / "project"
    workflows = project / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "jobs:\n  security:\n    steps:\n      - run: python -m pip_audit\n      - run: python -m bandit\n"
        "      - uses: github/codeql-action/analyze@v3\n",
        encoding="utf-8",
    )
    (workflows / "release.yml").write_text(
        "jobs:\n  release:\n    steps:\n      - uses: actions/attest-build-provenance@v2\n",
        encoding="utf-8",
    )
    (project / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (project / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    config = {
        "PROJECT_ROOT": str(project),
        "INSTANCE_PATH": str(tmp_path / "instance"),
        "LOGS_FOLDER": str(tmp_path / "instance" / "logs"),
        "UPLOAD_FOLDER": str(tmp_path / "instance" / "uploads" / "incoming"),
        "QUARANTINE_UPLOAD_FOLDER": str(tmp_path / "instance" / "uploads" / "quarantine"),
        "REPORTS_FOLDER": str(tmp_path / "instance" / "reports"),
        "BACKUP_ROOT": str(tmp_path / "instance" / "backups"),
        "SECURITY_HEADERS_ENABLED": True,
        "CSRF_ENABLED": True,
    }
    config.update(overrides)
    return create_app("testing", config)


def test_deployment_workspace_reports_repository_capability_not_pipeline_history(tmp_path) -> None:
    response = _app(tmp_path).test_client().get("/api/v1/admin/deployments")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["deployment_status"]["environment"] == "testing"
    assert len(payload["pipelines"]["definitions"]) == 2
    assert payload["pipelines"]["active_runs"] is None
    assert payload["pipelines"]["history_status"] == "unavailable"
    assert payload["failed_builds"]["status"] == "unavailable"
    assert payload["security"]["dependency_audit"] == "configured"
    assert payload["security"]["container_provenance"] == "configured"
    assert payload["security"]["scan_results"] is None


def test_deployment_verification_runs_real_checks_and_is_audited(tmp_path) -> None:
    app = _app(tmp_path)

    response = app.test_client().post("/api/v1/admin/deployments/verify", json={})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "passed_with_warnings"
    assert next(item for item in payload["checks"] if item["name"] == "Database connectivity")["status"] == "passed"
    assert next(item for item in payload["checks"] if item["name"] == "Release metadata")["status"] == "failed"
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        audit = database.session.scalar(select(AuditLog).where(AuditLog.action == "deployment.verification.completed"))
        assert audit is not None
        assert audit.result == "success"


def test_rollback_plan_requires_recorded_immutable_release(tmp_path) -> None:
    app = _app(tmp_path)
    client = app.test_client()

    rejected = client.post(
        "/api/v1/admin/deployments/rollback-plans",
        json={"target_version": "v0.9.0"},
    )
    assert rejected.status_code == 409

    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        database.session.add(
            Setting(
                namespace="deployment",
                key="release_catalog",
                value=json.dumps(
                    [
                        {
                            "version": "v0.9.0",
                            "digest": "sha256:" + "a" * 64,
                            "git_sha": "b" * 40,
                            "status": "previous",
                        }
                    ]
                ),
                value_type="json",
            )
        )
        database.session.commit()

    created = client.post(
        "/api/v1/admin/deployments/rollback-plans",
        json={"target_version": "v0.9.0"},
    )

    assert created.status_code == 201
    plan = created.get_json()
    assert plan["automatic_rollback_executed"] is False
    assert plan["target_digest"] == "sha256:" + "a" * 64


def test_deployment_workspace_enforces_server_side_rbac(tmp_path) -> None:
    response = (
        _app(tmp_path)
        .test_client()
        .get(
            "/api/v1/admin/deployments",
            headers={"X-CI-User": "analyst", "X-CI-Role": "user"},
        )
    )

    assert response.status_code == 403
