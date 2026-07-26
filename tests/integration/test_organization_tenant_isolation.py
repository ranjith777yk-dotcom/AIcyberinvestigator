from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from cyberinvestigator import create_app
from cyberinvestigator.infrastructure.database.migrations import DEFAULT_ORGANIZATION_ID
from cyberinvestigator.infrastructure.database.models import (
    AuditLog,
    Case,
    OrganizationMembership,
    Role,
    User,
)
from cyberinvestigator.infrastructure.security.web_security import hash_password

ADMIN_HEADERS = {"X-CI-User": "investigator", "X-CI-Role": "admin"}


def _create_organization(client, slug: str = "acme-security") -> str:
    response = client.post(
        "/api/v1/organizations",
        headers=ADMIN_HEADERS,
        json={
            "name": "Acme Security",
            "slug": slug,
            "reason": "Create an isolated customer organization.",
        },
    )
    assert response.status_code == 201
    assert response.get_json()["subscription_status"] is None
    return response.get_json()["id"]


def test_default_organization_preserves_single_tenant_compatibility() -> None:
    app = create_app("testing")
    client = app.test_client()

    organizations = client.get("/api/v1/organizations").get_json()
    assert organizations["active_organization_id"] == str(DEFAULT_ORGANIZATION_ID)
    assert organizations["items"][0]["slug"] == "default"

    created = client.post("/api/v1/cases", json={"case_number": "DEFAULT-1", "title": "Compatibility"})
    assert created.status_code == 201
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        case = database.session.get(Case, UUID(created.get_json()["id"]))
        assert case.organization_id == DEFAULT_ORGANIZATION_ID


def test_cases_and_admin_visibility_are_isolated_between_organizations() -> None:
    app = create_app("testing", {"MULTI_TENANT_ENABLED": True})
    client = app.test_client()
    organization_id = _create_organization(client)

    default_case = client.post("/api/v1/cases", json={"case_number": "SHARED-1", "title": "Default tenant"})
    assert default_case.status_code == 201
    tenant_headers = {**ADMIN_HEADERS, "X-CI-Organization": organization_id}
    tenant_case = client.post(
        "/api/v1/cases",
        headers=tenant_headers,
        json={"case_number": "SHARED-1", "title": "Acme tenant"},
    )
    assert tenant_case.status_code == 201

    default_items = client.get("/api/v1/cases").get_json()["items"]
    tenant_items = client.get("/api/v1/cases", headers=tenant_headers).get_json()["items"]
    assert [item["title"] for item in default_items] == ["Default tenant"]
    assert [item["title"] for item in tenant_items] == ["Acme tenant"]
    assert (
        client.get(f"/api/v1/cases/{default_case.get_json()['id']}/workspace", headers=tenant_headers).status_code
        == 403
    )


def test_non_member_cannot_select_another_organization() -> None:
    app = create_app("testing", {"MULTI_TENANT_ENABLED": True})
    client = app.test_client()
    organization_id = _create_organization(client, "restricted-org")
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        role = database.session.scalar(select(Role).where(Role.name == "user"))
        outsider = User(
            username="tenant-outsider",
            email="tenant-outsider@example.test",
            password_hash=hash_password("Password!123"),
            role_id=role.id,
        )
        database.session.add(outsider)
        database.session.flush()
        database.session.add(
            OrganizationMembership(
                organization_id=DEFAULT_ORGANIZATION_ID,
                user_id=outsider.id,
                organization_role="member",
                status="active",
            )
        )
        database.session.commit()

    denied = client.get(
        "/api/v1/cases",
        headers={
            "X-CI-User": "tenant-outsider",
            "X-CI-Role": "user",
            "X-CI-Organization": organization_id,
        },
    )
    assert denied.status_code == 403
    assert "membership" in denied.get_json()["error"]


def test_organization_settings_quotas_usage_and_invitations_are_real_and_audited() -> None:
    app = create_app("testing", {"MULTI_TENANT_ENABLED": True})
    client = app.test_client()
    organization_id = _create_organization(client, "quota-org")
    headers = {**ADMIN_HEADERS, "X-CI-Organization": organization_id}

    settings = client.put(
        "/api/v1/organizations/current/settings",
        headers=headers,
        json={
            "settings": {"timezone": "UTC", "default_case_severity": "high"},
            "reason": "Configure organization investigation defaults.",
        },
    )
    assert settings.status_code == 200
    assert (
        client.put(
            "/api/v1/organizations/current/quotas/investigations",
            headers=headers,
            json={"limit": 1, "enabled": True, "reason": "Apply reviewed investigation capacity."},
        ).status_code
        == 200
    )
    first = client.post(
        "/api/v1/cases",
        headers=headers,
        json={"case_number": "QUOTA-1", "title": "Allowed"},
    )
    assert first.status_code == 201
    assert first.get_json()["severity"] == "high"
    blocked = client.post(
        "/api/v1/cases",
        headers=headers,
        json={"case_number": "QUOTA-2", "title": "Blocked"},
    )
    assert blocked.status_code == 409

    invitation = client.post(
        "/api/v1/organizations/current/invitations",
        headers=headers,
        json={
            "email": "invitee@example.test",
            "organization_role": "member",
            "reason": "Invite an approved investigation team member.",
        },
    )
    assert invitation.status_code == 201
    assert invitation.get_json()["delivery_status"] == "unavailable"
    assert "token" not in invitation.get_json()

    workspace = client.get("/api/v1/organizations/current", headers=headers).get_json()
    assert workspace["usage"]["investigations"] == 1
    assert workspace["usage"]["members"] == 1
    assert workspace["organization_overview"]["subscription_status"] is None
    assert workspace["invitations"][0]["delivery_status"] == "unavailable"
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        actions = set(
            database.session.scalars(
                select(AuditLog.action).where(
                    AuditLog.organization_id == UUID(organization_id),
                    AuditLog.action.in_(
                        [
                            "organization.settings.updated",
                            "organization.quota.updated",
                            "organization.quota.blocked",
                            "organization.invitation.created",
                        ]
                    ),
                )
            )
        )
        assert actions == {
            "organization.settings.updated",
            "organization.quota.updated",
            "organization.quota.blocked",
            "organization.invitation.created",
        }


def test_organization_workspace_mobile_information_order() -> None:
    html = create_app("testing").test_client().get("/organizations").get_data(as_text=True)

    markers = ("Organization Overview", "Usage", "Members", "Invitations")
    assert [html.index(marker) for marker in markers] == sorted(html.index(marker) for marker in markers)
    assert "organization_workspace.css" in html
    assert "organization_workspace.js" in html
