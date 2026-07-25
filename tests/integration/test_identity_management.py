from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from cyberinvestigator import create_app
from cyberinvestigator.infrastructure.database.base import utc_now
from cyberinvestigator.infrastructure.database.models import AuditLog, Role, User, UserSession
from cyberinvestigator.infrastructure.security.web_security import hash_password


def _headers(username: str = "identity-admin", role: str = "admin") -> dict[str, str]:
    return {"X-CI-User": username, "X-CI-Role": role}


def test_identity_workspace_uses_persisted_users_roles_permissions_and_sessions() -> None:
    app = create_app("testing")

    response = app.test_client().get("/api/v1/admin/identity", headers=_headers())

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["summary"]["users"] == len(payload["users"])
    assert payload["summary"]["roles"] == len(payload["roles"])
    assert payload["summary"]["permissions"] == len(payload["permissions"])
    assert payload["capabilities"]["mfa"]["status"] == "not_configured"
    assert all("permissions" in role for role in payload["roles"])


def test_custom_role_lifecycle_and_user_assignment_are_audited() -> None:
    app = create_app("testing")
    client = app.test_client()
    role_response = client.post(
        "/api/v1/admin/roles",
        headers=_headers(),
        json={
            "name": "case_reviewer",
            "description": "Reviews investigation records.",
            "permission_codes": ["cases.read", "reports.read"],
        },
    )
    assert role_response.status_code == 201
    role = role_response.get_json()
    assert role["is_system"] is False
    assert role["permissions"] == ["cases.read", "reports.read"]

    updated = client.patch(
        f"/api/v1/admin/roles/{role['id']}",
        headers=_headers(),
        json={"permission_codes": ["cases.read", "reports.read", "timeline.read"]},
    )
    assert updated.status_code == 200
    assert "timeline.read" in updated.get_json()["permissions"]

    user = client.post(
        "/api/v1/admin/users",
        headers=_headers(),
        json={
            "username": "reviewer-one",
            "email": "reviewer@example.test",
            "password": "StrongPassword!123",
            "role": "case_reviewer",
        },
    )
    assert user.status_code == 201
    assert user.get_json()["user"]["role"] == "case_reviewer"
    assert client.delete(f"/api/v1/admin/roles/{role['id']}", headers=_headers()).status_code == 409

    disposable = client.post(
        "/api/v1/admin/roles",
        headers=_headers(),
        json={"name": "temporary_role", "permission_codes": []},
    )
    assert disposable.status_code == 201
    deleted = client.delete(
        f"/api/v1/admin/roles/{disposable.get_json()['id']}",
        headers=_headers(),
    )
    assert deleted.status_code == 200
    assert deleted.get_json()["deleted"] is True
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        actions = set(
            database.session.scalars(
                select(AuditLog.action).where(
                    AuditLog.action.in_(
                        ["admin.role.created", "admin.role.updated", "admin.role.deleted", "admin.user.create"]
                    )
                )
            )
        )
        assert actions == {"admin.role.created", "admin.role.updated", "admin.role.deleted", "admin.user.create"}


def test_disabling_account_revokes_active_sessions_and_session_action_is_audited() -> None:
    app = create_app("testing")
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        role = database.session.scalar(select(Role).where(Role.name == "user"))
        user = User(
            username="session-user",
            email="session@example.test",
            password_hash=hash_password("StrongPassword!123"),
            role_id=role.id,
            status="active",
        )
        database.session.add(user)
        database.session.flush()
        managed_session = UserSession(
            user_id=user.id,
            owner_user_id=user.id,
            created_by_user_id=user.id,
            session_token_hash="a" * 64,
            active=True,
            status="active",
            expires_at=utc_now() + timedelta(hours=1),
        )
        database.session.add(managed_session)
        database.session.commit()
        user_id = str(user.id)
        session_id = str(managed_session.id)
        managed_session_id = managed_session.id

    detail = app.test_client().get(f"/api/v1/admin/identity/users/{user_id}", headers=_headers())
    assert detail.status_code == 200
    assert detail.get_json()["security"]["active_sessions"] == 1

    disabled = app.test_client().patch(
        f"/api/v1/admin/users/{user_id}",
        headers=_headers(),
        json={"status": "suspended"},
    )
    assert disabled.status_code == 200
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        record = database.session.get(UserSession, managed_session_id)
        assert record.active is False
        assert record.status == "revoked"

    revoke = app.test_client().delete(
        f"/api/v1/admin/identity/sessions/{session_id}",
        headers=_headers(),
    )
    assert revoke.status_code == 200
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        assert database.session.scalar(select(AuditLog).where(AuditLog.action == "admin.session.revoked"))


def test_identity_mutations_require_server_side_permission_and_protect_final_admin() -> None:
    app = create_app("testing")
    client = app.test_client()
    assert (
        client.post(
            "/api/v1/admin/roles",
            headers=_headers("ordinary-user", "user"),
            json={"name": "forbidden_role"},
        ).status_code
        == 403
    )

    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        admin = database.session.scalar(select(User).join(Role).where(Role.name == "admin"))
        admin_id = str(admin.id)
        admin_name = admin.username

    response = client.patch(
        f"/api/v1/admin/users/{admin_id}",
        headers=_headers(admin_name, "admin"),
        json={"status": "suspended"},
    )
    assert response.status_code == 409
    assert "cannot disable" in response.get_json()["error"].lower()


def test_reauthentication_replaces_prior_server_side_session() -> None:
    app = create_app("testing", {"AUTH_REQUIRED": True})
    client = app.test_client()
    credentials = {
        "username": app.config["DEFAULT_USER"],
        "password": app.config["DEFAULT_ADMIN_PASSWORD"],
    }

    assert client.post("/login", data=credentials).status_code == 302
    assert client.post("/login", data=credentials).status_code == 302

    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        sessions = list(database.session.scalars(select(UserSession).order_by(UserSession.created_at)))
        assert sum(item.active for item in sessions) == 1
        assert any(item.status == "replaced" for item in sessions)


def test_locked_account_login_is_recorded_as_blocked() -> None:
    app = create_app("testing", {"AUTH_REQUIRED": True})
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        role = database.session.scalar(select(Role).where(Role.name == "user"))
        account = User(
            username="locked-user",
            email="locked@example.test",
            password_hash=hash_password("StrongPassword!123"),
            role_id=role.id,
            status="active",
            locked_until=utc_now() + timedelta(minutes=10),
        )
        database.session.add(account)
        database.session.commit()

    response = app.test_client().post(
        "/login",
        data={"username": "locked-user", "password": "StrongPassword!123"},
    )

    assert response.status_code == 200
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        audit = database.session.scalar(
            select(AuditLog).where(
                AuditLog.username == "locked-user",
                AuditLog.action == "auth.login",
                AuditLog.result == "blocked",
            )
        )
        assert audit is not None
        assert audit.reason == "locked account"
