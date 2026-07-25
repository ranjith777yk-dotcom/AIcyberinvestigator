from __future__ import annotations

from sqlalchemy import select

from cyberinvestigator import create_app
from cyberinvestigator.infrastructure.database.models import Notification, Role, User
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
