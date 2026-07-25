from __future__ import annotations

import json
import time
import zipfile
from io import BytesIO
from pathlib import Path

from sqlalchemy import select

from cyberinvestigator import create_app
from cyberinvestigator.infrastructure.database.models import AuditLog, Setting
from cyberinvestigator.infrastructure.security.credential_vault import CredentialVault


def _headers(role: str = "admin") -> dict[str, str]:
    return {"X-CI-User": "plugin-admin", "X-CI-Role": role}


def _write_connector(root: Path) -> None:
    plugin = root / "test-connector"
    plugin.mkdir()
    (plugin / "plugin.toml").write_text(
        """
[plugin]
identifier = "test-connector"
name = "Test Connector"
version = "1.0.0"
module = "connector.py"
object = "connector"
enabled = false
""".strip(),
        encoding="utf-8",
    )
    (plugin / "connector.py").write_text(
        """
from cyberinvestigator.infrastructure.integrations import ConnectorHealth, ConnectorHealthState, ConnectorSyncResult
from cyberinvestigator.infrastructure.plugins import PluginConfiguration, PluginMetadata

class TestConnector:
    metadata = PluginMetadata(
        identifier="test-connector",
        name="Test Connector",
        version="1.0.0",
        description="Test connector",
        capabilities=("synchronize",),
        category="siem",
        permissions=("network.egress",),
        configuration=PluginConfiguration(
            schema={
                "endpoint": {"type": "string", "label": "Endpoint"},
                "api_token": {"type": "string", "label": "API token", "secret": True},
            },
            defaults={"endpoint": "https://siem.example.test"},
        ),
    )

    def health(self, *, configuration, credentials):
        assert credentials["api_token"] == "connector-secret"
        return ConnectorHealth(
            state=ConnectorHealthState.AVAILABLE,
            message="Configured test endpoint responded.",
            checked_at="2026-07-26T10:00:00+00:00",
        )

    def synchronize(self, *, configuration, credentials, cursor):
        assert credentials["api_token"] == "connector-secret"
        return ConnectorSyncResult(
            status="completed",
            records_processed=3,
            message="Three source records synchronized.",
            completed_at="2026-07-26T10:01:00+00:00",
            cursor="cursor-3",
        )

connector = TestConnector()
""".strip(),
        encoding="utf-8",
    )


def _wait_for_job(client, job_id: str) -> dict[str, object]:
    for _ in range(100):
        response = client.get(f"/api/v1/admin/plugins/jobs/{job_id}", headers=_headers())
        payload = response.get_json()
        if payload["status"] in {"completed", "failed"}:
            return payload
        time.sleep(0.01)
    raise AssertionError("Plugin job did not complete.")


def test_connector_configuration_permissions_health_and_sync_are_real_and_audited(tmp_path: Path) -> None:
    _write_connector(tmp_path)
    app = create_app("testing", {"PLUGINS_FOLDER": str(tmp_path), "PLUGINS_ENABLED": True})
    client = app.test_client()

    management = client.get("/api/v1/admin/plugins/management", headers=_headers())
    assert management.status_code == 200
    plugin = management.get_json()["plugins"][0]
    assert plugin["category"] == "siem"
    assert plugin["requested_permissions"] == ["network.egress"]
    assert plugin["connector_operations"] == ["health", "sync"]
    assert management.get_json()["updates"] == []
    assert "unknown" in management.get_json()["updates_notice"]

    denied_enable = client.post("/api/v1/plugins/test-connector/enable", headers=_headers())
    assert denied_enable.status_code == 400
    invalid_configuration = client.patch(
        "/api/v1/admin/plugins/test-connector/configuration",
        headers=_headers(),
        json={
            "configuration": {"endpoint": 42},
            "credentials": {},
            "granted_permissions": [],
        },
    )
    assert invalid_configuration.status_code == 400

    configured = client.patch(
        "/api/v1/admin/plugins/test-connector/configuration",
        headers=_headers(),
        json={
            "configuration": {"endpoint": "https://siem.example.test"},
            "credentials": {"api_token": "connector-secret"},
            "granted_permissions": ["network.egress"],
        },
    )
    assert configured.status_code == 200
    assert "connector-secret" not in configured.get_data(as_text=True)
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        secret = database.session.scalar(
            select(Setting).where(Setting.namespace == "secret.plugin", Setting.key == "test-connector")
        )
        assert secret is not None
        assert "connector-secret" not in secret.value
        decrypted = CredentialVault(app.config["SECRET_KEY"]).decrypt(secret.value)
        assert json.loads(decrypted)["api_token"] == "connector-secret"

    assert client.post("/api/v1/plugins/test-connector/enable", headers=_headers()).status_code == 200
    health = client.post("/api/v1/admin/plugins/test-connector/health", headers=_headers())
    assert health.status_code == 202
    health_job = _wait_for_job(client, health.get_json()["id"])
    assert health_job["status"] == "completed"
    assert health_job["result"]["state"] == "available"

    sync = client.post("/api/v1/admin/plugins/test-connector/sync", headers=_headers())
    assert sync.status_code == 202
    sync_job = _wait_for_job(client, sync.get_json()["id"])
    assert sync_job["result"]["records_processed"] == 3
    refreshed = client.get("/api/v1/admin/plugins/management", headers=_headers()).get_json()
    assert refreshed["health"]["test-connector"]["state"] == "available"
    assert refreshed["synchronizations"]["test-connector"]["cursor"] == "cursor-3"
    removed = client.post("/api/v1/plugins/test-connector/delete", headers=_headers())
    assert removed.status_code == 200
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        actions = set(database.session.scalars(select(AuditLog.action).where(AuditLog.action.like("admin.plugin.%"))))
        assert {
            "admin.plugin.configuration.updated",
            "admin.plugin.enable",
            "admin.plugin.health.queued",
            "admin.plugin.health.completed",
            "admin.plugin.sync.queued",
            "admin.plugin.sync.completed",
            "admin.plugin.delete",
        }.issubset(actions)
        assert (
            database.session.scalar(
                select(Setting).where(Setting.namespace == "secret.plugin", Setting.key == "test-connector")
            )
            is None
        )


def test_plugin_management_requires_server_side_permission(tmp_path: Path) -> None:
    _write_connector(tmp_path)
    app = create_app("testing", {"PLUGINS_FOLDER": str(tmp_path), "PLUGINS_ENABLED": True})

    response = app.test_client().get("/api/v1/admin/plugins/management", headers=_headers("user"))

    assert response.status_code == 403


def test_uploaded_archive_requires_hash_bound_manifest(tmp_path: Path) -> None:
    app = create_app("testing", {"PLUGINS_FOLDER": str(tmp_path), "PLUGINS_ENABLED": True})
    archive = BytesIO()
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr(
            "plugin.toml",
            '[plugin]\nidentifier="unsafe"\nname="Unsafe"\nversion="1"\nmodule="plugin.py"\nobject="plugin"\n',
        )
        package.writestr("plugin.py", "plugin = None")
    archive.seek(0)

    response = app.test_client().post(
        "/api/v1/plugins/upload",
        headers=_headers(),
        data={"plugin": (archive, "unsafe.zip")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert "SHA-256" in response.get_json()["error"]
