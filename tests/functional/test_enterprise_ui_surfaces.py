from __future__ import annotations

from cyberinvestigator import create_app


def test_enterprise_workspace_pages_render_their_operational_surfaces() -> None:
    app = create_app("testing")
    client = app.test_client()
    pages = {
        "/": ("Security Operations Center", "Threat Trend", "Current Investigation"),
        "/cases": ("Investigation cases", "Case details", "Investigation Data"),
        "/evidence": ("Evidence repository", "Forensic report"),
        "/timeline": ("Investigation timeline", "AI timeline summary"),
        "/reports": ("Investigation reports", "ZIP Package"),
        "/ai-chat": ("Investigation chat", "Recent conversations", "stop-generation"),
        "/profile": ("Profile settings", "Session Management", "API Usage"),
        "/plugins": ("Plugin registry", "Marketplace Ready"),
        "/settings": ("Platform settings", "AI Providers", "Integrations"),
        "/admin": ("Operations dashboard", "Security", "admin-user-modal"),
    }
    for path, markers in pages.items():
        response = client.get(path)
        assert response.status_code == 200, path
        html = response.get_data(as_text=True)
        for marker in markers:
            assert marker in html, (path, marker)


def test_user_navigation_excludes_administration_features() -> None:
    app = create_app("testing")
    response = app.test_client().get("/", headers={"X-CI-Role": "user", "X-CI-User": "ui-user"})
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "User Management" not in html
    assert "Security Center" not in html
    assert "Plugin Status" not in html
    for label in ("Cases", "Evidence", "Timeline", "Reports", "AI Chat", "Profile", "Settings", "Notifications"):
        assert label in html
