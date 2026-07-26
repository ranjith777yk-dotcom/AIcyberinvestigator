from __future__ import annotations

from cyberinvestigator import create_app


def test_developer_portal_is_authenticated_responsive_and_search_first() -> None:
    app = create_app("testing")
    response = app.test_client().get("/developers")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    markers = ("Documentation Search", "API Reference", "Guides", "Release Notes")
    assert [html.index(marker) for marker in markers] == sorted(html.index(marker) for marker in markers)
    assert "developer_portal.css" in html
    assert "developer_portal.js" in html


def test_openapi_visibility_and_version_headers_follow_rbac() -> None:
    app = create_app("testing")
    client = app.test_client()

    user_response = client.get(
        "/api/v1/openapi.json",
        headers={"X-CI-Role": "user", "X-CI-User": "developer"},
    )
    assert user_response.status_code == 200
    assert user_response.headers["API-Version"] == "v1"
    user_spec = user_response.get_json()
    assert "/admin/users" not in user_spec["paths"]
    assert "/cases" in user_spec["paths"]

    admin_spec = client.get("/api/v1/openapi.json").get_json()
    assert "/admin/users" in admin_spec["paths"]
    assert admin_spec["paths"]["/admin/users"]["get"]["x-required-permissions"] == ["users.manage"]


def test_developer_catalog_reports_actual_and_unavailable_capabilities() -> None:
    response = create_app("testing").test_client().get("/api/v1/developer/catalog")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["api"]["version"] == "v1"
    assert payload["api"]["operation_count"] > 0
    assert payload["sdks"]["python"]["status"] == "preview"
    assert payload["webhooks"]["subscription_api"] == "unavailable"
    assert payload["webhooks"]["delivery_worker"] == "unavailable"
    assert payload["release_notes"]["status"] == "available"
