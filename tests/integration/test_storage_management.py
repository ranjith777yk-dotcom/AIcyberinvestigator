"""Integration coverage for storage health, custody integrity, and verified recovery points."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import select

from cyberinvestigator import create_app
from cyberinvestigator.infrastructure.database.models import AuditLog, Notification


def _app(tmp_path):
    return create_app(
        "testing",
        {
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{(tmp_path / 'instance' / 'test.db').as_posix()}",
            "INSTANCE_PATH": str(tmp_path / "instance"),
            "UPLOAD_FOLDER": str(tmp_path / "uploads" / "incoming"),
            "QUARANTINE_UPLOAD_FOLDER": str(tmp_path / "uploads" / "quarantine"),
            "REPORTS_FOLDER": str(tmp_path / "reports"),
            "LOGS_FOLDER": str(tmp_path / "logs"),
            "BACKUP_ROOT": str(tmp_path / "backups"),
        },
    )


def _case_and_evidence(client):
    case = client.post("/api/v1/cases", json={"case_number": "ST-001", "title": "Storage test"}).get_json()
    evidence = client.post(
        "/api/v1/evidence",
        json={
            "case_id": case["id"],
            "evidence_number": "EV-ST-1",
            "filename": "artifact.bin",
            "content": "preserved evidence bytes",
        },
    ).get_json()
    return case, evidence


def test_storage_workspace_uses_measured_provider_and_capacity_data(tmp_path) -> None:
    app = _app(tmp_path)

    response = app.test_client().get("/api/v1/admin/storage")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["provider"]["id"] == "local-filesystem"
    assert payload["provider"]["status"] == "available"
    assert payload["capacity"]["status"] == "available"
    assert payload["capacity"]["total_bytes"] > 0
    assert payload["recovery"]["rpo"] is None
    assert payload["recovery"]["rto"] is None
    assert payload["encryption"]["at_rest"]["status"] == "unverified"


def test_backup_is_manifested_verified_and_tampering_is_detected(tmp_path) -> None:
    app = _app(tmp_path)
    client = app.test_client()
    _case_and_evidence(client)

    created = client.post("/api/v1/admin/storage/backups", json={})

    assert created.status_code == 201
    backup = created.get_json()
    assert backup["verification"]["valid"] is True
    assert backup["file_count"] >= 2
    backup_root = Path(app.config["BACKUP_ROOT"]) / backup["backup_id"]
    target = next(
        path
        for path in backup_root.rglob("*")
        if path.is_file() and not path.name.startswith(".") and path.name != "manifest.json"
    )
    target.write_bytes(target.read_bytes() + b"tampered")

    verification = client.post(f"/api/v1/admin/storage/backups/{backup['backup_id']}/verify", json={})

    assert verification.status_code == 409
    assert verification.get_json()["valid"] is False
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        assert database.session.scalar(select(AuditLog).where(AuditLog.action == "storage.backup.verification_failed"))
        assert database.session.scalar(select(Notification).where(Notification.title == "Backup verification failed"))


def test_verified_backup_produces_plan_without_online_restore(tmp_path) -> None:
    app = _app(tmp_path)
    client = app.test_client()
    backup = client.post("/api/v1/admin/storage/backups", json={}).get_json()

    response = client.post(
        "/api/v1/admin/storage/restore-plans",
        json={"backup_id": backup["backup_id"]},
    )

    assert response.status_code == 201
    plan = response.get_json()
    assert plan["status"] == "ready_for_offline_restore"
    assert plan["automatic_restore_executed"] is False
    workspace = client.get("/api/v1/admin/storage").get_json()
    assert workspace["recent_restores"][0]["backup_id"] == backup["backup_id"]


def test_evidence_integrity_verification_uses_recorded_hash_and_size(tmp_path) -> None:
    app = _app(tmp_path)
    client = app.test_client()
    _, evidence = _case_and_evidence(client)

    initial = client.post("/api/v1/admin/storage/integrity/verify", json={})
    assert initial.status_code == 200
    assert initial.get_json()["valid"] is True

    custody_path = Path(app.config["QUARANTINE_UPLOAD_FOLDER"]) / evidence["storage_path"]
    custody_path.write_bytes(b"changed")
    failed = client.post("/api/v1/admin/storage/integrity/verify", json={})

    assert failed.status_code == 409
    assert failed.get_json()["failures"][0]["evidence_id"] == evidence["id"]


def test_legal_hold_blocks_evidence_removal_and_is_audited(tmp_path) -> None:
    app = _app(tmp_path)
    client = app.test_client()
    case, evidence = _case_and_evidence(client)

    hold = client.patch(
        f"/api/v1/admin/storage/legal-holds/{case['id']}",
        json={"active": True, "reason": "Preservation order 2026-17"},
    )
    deleted = client.delete(f"/api/v1/evidence/{evidence['id']}")

    assert hold.status_code == 200
    assert deleted.status_code == 409
    assert "legal hold" in deleted.get_json()["error"]
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        assert database.session.scalar(select(AuditLog).where(AuditLog.action == "storage.legal_hold.applied"))


def test_storage_management_requires_admin_permission(tmp_path) -> None:
    response = (
        _app(tmp_path)
        .test_client()
        .get(
            "/api/v1/admin/storage",
            headers={"X-CI-User": "analyst", "X-CI-Role": "user"},
        )
    )

    assert response.status_code == 403
