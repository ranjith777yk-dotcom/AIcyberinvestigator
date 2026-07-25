from __future__ import annotations

from sqlalchemy import select

from cyberinvestigator import create_app
from cyberinvestigator.infrastructure.database.models import AuditLog, Notification, Role, User
from cyberinvestigator.infrastructure.security.web_security import hash_password


def _headers(username: str, role: str = "user") -> dict[str, str]:
    return {"X-CI-User": username, "X-CI-Role": role}


def test_user_objects_are_isolated_and_admin_bypasses_scope() -> None:
    app = create_app("testing")
    with app.app_context():
        db = app.extensions["cyberinvestigator_database"]
        role = db.session.scalar(select(Role).where(Role.name == "user"))
        first = User(
            username="owner-one", email="one@example.test", password_hash=hash_password("Password!123"), role_id=role.id
        )
        second = User(
            username="owner-two", email="two@example.test", password_hash=hash_password("Password!123"), role_id=role.id
        )
        db.session.add_all([first, second])
        db.session.commit()
        first_id, second_id = first.id, second.id

    client = app.test_client()
    case = client.post(
        "/api/v1/cases", headers=_headers("owner-one"), json={"case_number": "RBAC-ONE", "title": "Private"}
    )
    assert case.status_code == 201
    case_id = case.get_json()["id"]
    assert case.get_json()["owner_user_id"] == str(first_id)

    assert (
        client.post(
            "/api/v1/evidence",
            headers=_headers("owner-one"),
            json={"case_id": case_id, "evidence_number": "EV-RBAC", "filename": "private.txt", "content": "secret"},
        ).status_code
        == 201
    )
    evidence_id = client.get("/api/v1/evidence", headers=_headers("owner-one")).get_json()["items"][0]["id"]
    job = client.post(f"/api/v1/evidence/{evidence_id}/analysis-jobs", headers=_headers("owner-one"))
    assert job.status_code == 202
    job_id = job.get_json()["id"]
    assert client.get(f"/api/v1/evidence/analysis-jobs/{job_id}", headers=_headers("owner-two")).status_code == 403
    assert (
        client.get(f"/api/v1/evidence/analysis-jobs/{job_id}", headers=_headers("investigator", "admin")).status_code
        == 200
    )
    assert (
        client.post(
            "/api/v1/timeline",
            headers=_headers("owner-one"),
            json={"case_id": case_id, "event_type": "observation.manual", "summary": "private event"},
        ).status_code
        == 201
    )
    assert client.post("/api/v1/reports", headers=_headers("owner-one"), json={"case_id": case_id}).status_code == 201
    greeting = client.post(
        "/api/v1/ai/chat", headers=_headers("owner-one"), json={"case_id": case_id, "message": "hello"}
    )
    assert greeting.status_code == 200
    assert greeting.get_json()["provider_status"]["provider"] == "local"
    assert greeting.get_json()["provider_status"]["provider_called"] is False

    workspace = client.get(f"/api/v1/cases/{case_id}/workspace", headers=_headers("owner-one"))
    assert workspace.status_code == 200
    workspace_payload = workspace.get_json()
    assert workspace_payload["case"]["id"] == case_id
    assert workspace_payload["counts"]["evidence"] == 1
    assert workspace_payload["counts"]["timeline"] >= 2
    assert workspace_payload["counts"]["reports"] == 1
    assert client.get(f"/api/v1/cases/{case_id}/workspace", headers=_headers("owner-two")).status_code == 403
    assert (
        client.get(f"/api/v1/cases/{case_id}/workspace", headers=_headers("investigator", "admin")).status_code == 200
    )
    assert client.post(f"/api/v1/cases/{case_id}/close", headers=_headers("owner-one")).status_code == 200
    lifecycle_workspace = client.get(f"/api/v1/cases/{case_id}/workspace", headers=_headers("owner-one")).get_json()
    assert lifecycle_workspace["case"]["status"] == "closed"
    assert any(item["event_type"] == "case.closed" for item in lifecycle_workspace["timeline"])
    with app.app_context():
        db = app.extensions["cyberinvestigator_database"]
        audit = db.session.scalar(
            select(AuditLog)
            .where(AuditLog.action == "case.closed", AuditLog.affected_object == f"case:{case_id}")
            .order_by(AuditLog.created_at.desc())
        )
        assert audit is not None
        assert audit.username == "owner-one"
        assert audit.result == "success"

    streamed = client.post("/api/v1/ai/chat/stream", headers=_headers("owner-one"), json={"message": "hello"})
    assert streamed.status_code == 200
    assert '"provider":"local"' in streamed.get_data(as_text=True).replace(" ", "")

    for path in (
        "/api/v1/cases",
        "/api/v1/evidence",
        "/api/v1/timeline",
        "/api/v1/reports",
        "/api/v1/ai/conversations",
    ):
        assert client.get(path, headers=_headers("owner-two")).get_json()["items"] == []
        assert client.get(path, headers=_headers("investigator", "admin")).get_json()["items"]
    assert (
        client.get("/api/v1/reports", headers=_headers("owner-two"), query_string={"case_id": case_id}).get_json()[
            "items"
        ]
        == []
    )
    assert (
        client.patch(f"/api/v1/cases/{case_id}", headers=_headers("owner-two"), json={"title": "stolen"}).status_code
        == 403
    )

    with app.app_context():
        db = app.extensions["cyberinvestigator_database"]
        db.session.add_all(
            [
                Notification(
                    user_id=first_id,
                    owner_user_id=first_id,
                    created_by_user_id=first_id,
                    title="One",
                    message="private",
                ),
                Notification(
                    user_id=second_id,
                    owner_user_id=second_id,
                    created_by_user_id=second_id,
                    title="Two",
                    message="private",
                ),
            ]
        )
        db.session.commit()
    assert [
        item["title"] for item in client.get("/api/v1/notifications", headers=_headers("owner-one")).get_json()["items"]
    ] == ["One"]
    assert {
        item["title"]
        for item in client.get("/api/v1/notifications", headers=_headers("investigator", "admin")).get_json()["items"]
    } >= {"One", "Two"}
    owner_history_response = client.get("/api/v1/history", headers=_headers("owner-one"))
    assert owner_history_response.status_code == 200, owner_history_response.get_data(as_text=True)
    owner_history = owner_history_response.get_json()
    assert [item["title"] for item in owner_history["notifications"]["items"]] == ["One"]
    assert owner_history["scope"]["administrator"] is False
    assert owner_history["audit_integrity"]["available"] is False
    assert all(item["case_id"] == case_id for item in owner_history["investigation_activity"])

    admin_history = client.get("/api/v1/history", headers=_headers("investigator", "admin")).get_json()
    assert admin_history["scope"]["administrator"] is True
    assert "valid" in admin_history["audit_integrity"]


def test_user_cannot_access_admin_routes() -> None:
    app = create_app("testing")
    client = app.test_client()
    for path in (
        "/admin",
        "/settings",
        "/plugins",
        "/api/v1/admin/overview",
        "/api/v1/security/soc",
        "/api/v1/monitoring/metrics",
    ):
        assert client.get(path, headers=_headers("ordinary-user")).status_code == 403
