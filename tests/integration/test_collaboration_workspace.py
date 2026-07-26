from __future__ import annotations

from sqlalchemy import select

from cyberinvestigator import create_app
from cyberinvestigator.infrastructure.database.migrations import DEFAULT_ORGANIZATION_ID
from cyberinvestigator.infrastructure.database.models import (
    AuditLog,
    Notification,
    OrganizationMembership,
    Role,
    User,
)
from cyberinvestigator.infrastructure.security.web_security import hash_password

ADMIN = {"X-CI-User": "investigator", "X-CI-Role": "admin"}


def _add_org_user(app, username: str = "case-collaborator") -> User:
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        role = database.session.scalar(select(Role).where(Role.name == "user"))
        user = User(
            username=username,
            email=f"{username}@example.test",
            password_hash=hash_password("Password!123"),
            role_id=role.id,
            status="active",
        )
        database.session.add(user)
        database.session.flush()
        database.session.add(
            OrganizationMembership(
                organization_id=DEFAULT_ORGANIZATION_ID,
                user_id=user.id,
                organization_role="member",
                status="active",
            )
        )
        database.session.commit()
        database.session.refresh(user)
        database.session.expunge(user)
        return user


def test_case_team_tasks_threads_mentions_reviews_and_audits_are_integrated() -> None:
    app = create_app("testing", {"MULTI_TENANT_ENABLED": True})
    client = app.test_client()
    collaborator = _add_org_user(app)
    user_headers = {"X-CI-User": collaborator.username, "X-CI-Role": "user"}

    case = client.post(
        "/api/v1/cases",
        headers=ADMIN,
        json={"case_number": "COLLAB-1", "title": "Shared investigation"},
    ).get_json()
    member = client.post(
        f"/api/v1/cases/{case['id']}/team",
        headers=ADMIN,
        json={"user_id": str(collaborator.id), "team_role": "investigator"},
    )
    assert member.status_code == 201
    assert client.get(f"/api/v1/cases/{case['id']}/workspace", headers=user_headers).status_code == 200

    task = client.post(
        f"/api/v1/cases/{case['id']}/tasks",
        headers=ADMIN,
        json={"title": "Validate indicators", "assignee_user_id": str(collaborator.id), "priority": "high"},
    )
    assert task.status_code == 201
    completed = client.patch(
        f"/api/v1/collaboration/tasks/{task.get_json()['id']}",
        headers=user_headers,
        json={"status": "completed"},
    )
    assert completed.status_code == 200
    assert completed.get_json()["completed_at"] is not None

    thread = client.post(
        f"/api/v1/cases/{case['id']}/discussions",
        headers=ADMIN,
        json={"title": "Indicator validation"},
    ).get_json()
    private_note = client.post(
        f"/api/v1/collaboration/discussions/{thread['id']}/comments",
        headers=ADMIN,
        json={"body": "Private lead note", "visibility": "private"},
    )
    assert private_note.status_code == 201
    mention = client.post(
        f"/api/v1/collaboration/discussions/{thread['id']}/comments",
        headers=ADMIN,
        json={"body": f"@{collaborator.username} please confirm the source.", "visibility": "team"},
    )
    assert mention.status_code == 201
    reply = client.post(
        f"/api/v1/collaboration/discussions/{thread['id']}/comments",
        headers=user_headers,
        json={"body": "Source confirmed.", "parent_comment_id": mention.get_json()["id"]},
    )
    assert reply.status_code == 201
    user_workspace = client.get(f"/api/v1/cases/{case['id']}/collaboration", headers=user_headers).get_json()
    bodies = [comment["body"] for item in user_workspace["threads"] for comment in item["comments"]]
    assert "Private lead note" not in bodies
    assert "Source confirmed." in bodies

    review = client.post(
        f"/api/v1/cases/{case['id']}/reviews",
        headers=ADMIN,
        json={"reviewer_user_id": str(collaborator.id), "request_note": "Validate conclusions."},
    )
    assert review.status_code == 201
    decision = client.patch(
        f"/api/v1/collaboration/reviews/{review.get_json()['id']}",
        headers=user_headers,
        json={"decision": "approved", "decision_note": "Conclusions match the evidence."},
    )
    assert decision.status_code == 200
    assert decision.get_json()["status"] == "approved"

    dashboard = client.get("/api/v1/collaboration", headers=user_headers).get_json()
    assert dashboard["assigned_tasks"][0]["status"] == "completed"
    assert any(item["author"] == "investigator" for item in dashboard["mentions"])
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        notifications = list(
            database.session.scalars(
                select(Notification).where(
                    Notification.organization_id == DEFAULT_ORGANIZATION_ID,
                    Notification.owner_user_id == collaborator.id,
                )
            )
        )
        actions = set(
            database.session.scalars(
                select(AuditLog.action).where(
                    AuditLog.organization_id == DEFAULT_ORGANIZATION_ID,
                    AuditLog.action.like("collaboration.%"),
                )
            )
        )
        assert {item.category for item in notifications} >= {"assignment", "mention", "review"}
        assert {
            "collaboration.team_member.added",
            "collaboration.task.created",
            "collaboration.task.updated",
            "collaboration.comment.created",
            "collaboration.review.requested",
            "collaboration.review.approved",
        } <= actions


def test_collaboration_records_cannot_cross_active_organization() -> None:
    app = create_app("testing", {"MULTI_TENANT_ENABLED": True})
    client = app.test_client()
    case = client.post(
        "/api/v1/cases",
        headers=ADMIN,
        json={"case_number": "COLLAB-BOUNDARY", "title": "Default tenant"},
    ).get_json()
    organization = client.post(
        "/api/v1/organizations",
        headers=ADMIN,
        json={"name": "Second Tenant", "slug": "collaboration-second", "reason": "Isolation test."},
    ).get_json()
    second = {**ADMIN, "X-CI-Organization": organization["id"]}
    assert client.get(f"/api/v1/cases/{case['id']}/collaboration", headers=second).status_code == 403


def test_observer_can_read_but_cannot_mutate_case_collaboration() -> None:
    app = create_app("testing", {"MULTI_TENANT_ENABLED": True})
    client = app.test_client()
    observer = _add_org_user(app, "case-observer")
    headers = {"X-CI-User": observer.username, "X-CI-Role": "user"}
    case = client.post(
        "/api/v1/cases",
        headers=ADMIN,
        json={"case_number": "COLLAB-OBSERVER", "title": "Read-only participant"},
    ).get_json()
    assert (
        client.post(
            f"/api/v1/cases/{case['id']}/team",
            headers=ADMIN,
            json={"user_id": str(observer.id), "team_role": "observer"},
        ).status_code
        == 201
    )
    assert client.get(f"/api/v1/cases/{case['id']}/collaboration", headers=headers).status_code == 200
    denied = client.post(
        f"/api/v1/cases/{case['id']}/discussions",
        headers=headers,
        json={"title": "Unauthorized mutation"},
    )
    assert denied.status_code == 403


def test_collaboration_mobile_information_order() -> None:
    html = create_app("testing").test_client().get("/collaboration").get_data(as_text=True)
    labels = ("Assigned Tasks", "Investigation Updates", "Comments", "Mentions")
    assert [html.index(label) for label in labels] == sorted(html.index(label) for label in labels)
    assert "collaboration_workspace.css" in html
    assert 'aria-live="polite"' in html


def test_mobile_companion_serializes_live_notifications() -> None:
    app = create_app("testing")
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        investigator = database.session.scalar(select(User).where(User.username == "investigator"))
        assert investigator is not None
        database.session.add(
            Notification(
                organization_id=DEFAULT_ORGANIZATION_ID,
                owner_user_id=investigator.id,
                title="Case review requested",
                message="Review the evidence-backed conclusion.",
                category="review",
                priority="high",
            )
        )
        database.session.commit()

    response = app.test_client().get("/api/v1/mobile/companion", headers=ADMIN)

    assert response.status_code == 200
    notification = response.get_json()["notifications"][0]
    assert notification["title"] == "Case review requested"
    assert notification["priority"] == "high"
