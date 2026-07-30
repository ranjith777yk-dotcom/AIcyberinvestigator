from __future__ import annotations

from sqlalchemy import select

from cyberinvestigator import create_app
from cyberinvestigator.infrastructure.database.models import AuditLog, Setting
from cyberinvestigator.infrastructure.security.credential_vault import CredentialVault


def _headers(role: str = "admin") -> dict[str, str]:
    return {"X-CI-User": "ai-platform-admin", "X-CI-Role": role}


def test_ai_management_reports_registered_state_without_synthetic_usage() -> None:
    app = create_app("testing")
    response = app.test_client().get("/api/v1/admin/ai/management", headers=_headers())

    assert response.status_code == 200
    payload = response.get_json()
    assert {item["provider"] for item in payload["providers"]} == {
        "nvidia",
        "ollama",
        "openai",
        "gemini",
        "claude",
        "perplexity",
        "openrouter",
        "groq",
        "deepseek",
        "custom",
    }
    assert payload["usage"] == []
    assert "Latency and cost are unavailable" in payload["usage_notice"]
    assert all(item["credential_exposed"] is False for item in payload["providers"])
    assert "chat.investigation" in payload["workloads"]


def test_provider_credential_is_encrypted_redacted_and_audited() -> None:
    app = create_app("testing", {"SECRET_KEY": "test-secret-key-that-is-long-enough-for-vault"})
    client = app.test_client()
    secret = "provider-secret-value"

    response = client.patch(
        "/api/v1/admin/ai/providers/openai",
        headers=_headers(),
        json={"model": "gpt-test-model", "credential": secret},
    )

    assert response.status_code == 200
    assert secret not in response.get_data(as_text=True)
    assert secret not in client.get("/api/v1/settings", headers=_headers()).get_data(as_text=True)
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        encrypted = database.session.scalar(
            select(Setting).where(Setting.namespace == "secret.ai", Setting.key == "openai")
        )
        assert encrypted is not None
        assert encrypted.value != secret
        assert CredentialVault(app.config["SECRET_KEY"]).decrypt(encrypted.value) == secret
        audit = database.session.scalar(select(AuditLog).where(AuditLog.action == "admin.ai_provider.updated"))
        assert audit is not None
        assert secret not in str(audit.reason)


def test_workload_prompt_and_failover_changes_are_persisted_and_audited() -> None:
    app = create_app("testing")
    client = app.test_client()
    workload = client.patch(
        "/api/v1/admin/ai/workloads/chat.investigation",
        headers=_headers(),
        json={"provider": "ollama", "model": "forensic-model:latest"},
    )
    assert workload.status_code == 200

    prompt = client.post(
        "/api/v1/admin/ai/prompts",
        headers=_headers(),
        json={
            "workload": "chat.investigation",
            "version": "v2",
            "content": "Prioritize chain-of-custody references.",
            "activate": True,
        },
    )
    assert prompt.status_code == 201
    assert (
        client.post(
            "/api/v1/admin/ai/prompts",
            headers=_headers(),
            json={
                "workload": "chat.investigation",
                "version": "v2",
                "content": "Replacement content is prohibited.",
            },
        ).status_code
        == 409
    )

    failover = client.patch(
        "/api/v1/admin/ai/failover",
        headers=_headers(),
        json={"enabled": False, "order": ["ollama", "openai"]},
    )
    assert failover.status_code == 200
    management = client.get("/api/v1/admin/ai/management", headers=_headers()).get_json()
    assert management["workloads"]["chat.investigation"]["model"] == "forensic-model:latest"
    assert management["failover"] == {"enabled": False, "order": ["ollama", "openai"]}
    assert any(item["version"] == "v2" and item["active"] for item in management["prompt_versions"])
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        actions = set(database.session.scalars(select(AuditLog.action).where(AuditLog.action.like("admin.ai_%"))))
        assert {
            "admin.ai_workload.updated",
            "admin.ai_prompt.created",
            "admin.ai_failover.updated",
        }.issubset(actions)


def test_ai_management_mutations_require_server_side_permission() -> None:
    app = create_app("testing")
    response = app.test_client().patch(
        "/api/v1/admin/ai/failover",
        headers=_headers("user"),
        json={"enabled": True, "order": ["ollama"]},
    )
    assert response.status_code == 403


def test_provider_can_be_disabled_without_exposing_credentials() -> None:
    app = create_app("testing")
    client = app.test_client()

    response = client.patch(
        "/api/v1/admin/ai/providers/nvidia",
        headers=_headers(),
        json={"enabled": False},
    )

    assert response.status_code == 200
    nvidia = next(item for item in response.get_json()["providers"] if item["provider"] == "nvidia")
    assert nvidia["enabled"] is False
    assert nvidia["credential_exposed"] is False


def test_local_provider_endpoint_requires_an_explicitly_allowed_host() -> None:
    app = create_app("testing")
    response = app.test_client().patch(
        "/api/v1/admin/ai/providers/ollama",
        headers=_headers(),
        json={"endpoint": "http://169.254.169.254/latest/meta-data"},
    )

    assert response.status_code == 400
    assert "AI_ALLOWED_PROVIDER_HOSTS" in response.get_json()["error"]
