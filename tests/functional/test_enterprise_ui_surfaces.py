from __future__ import annotations

from cyberinvestigator import create_app


def test_enterprise_workspace_pages_render_their_operational_surfaces() -> None:
    app = create_app("testing")
    client = app.test_client()
    pages = {
        "/": ("Security Operations Center", "AI Daily Briefing", "Priority Queue", "Current Investigation"),
        "/cases": ("Investigation cases", "Investigation workspace", "AI investigation summary", "Investigation Data"),
        "/evidence": (
            "Evidence repository",
            "Evidence analysis workspace",
            "Static analysis boundary",
            "Threat Intelligence Correlation Engine",
        ),
        "/timeline": (
            "Timeline Reconstruction",
            "AI timeline summary",
            "Related evidence",
            "Supported attack progression",
        ),
        "/reports": ("Professional Forensic Reporting", "Report editor", "Investigator annotation"),
        "/ai-chat": ("AI Investigation Engine", "Recent conversations", "stop-generation", "Supporting records"),
        "/profile": ("Profile settings", "Session Management", "Notification, Audit Trail", "Critical notifications"),
        "/plugins": ("Plugin, Integration &amp; Connector Framework", "Plugin health", "Marketplace preparation"),
        "/settings": ("Platform settings", "AI Providers", "Integrations"),
        "/admin": (
            "Administration &amp; Platform Operations Center",
            "Critical alerts",
            "Maintenance mode",
            "admin-user-modal",
        ),
    }
    for path, markers in pages.items():
        response = client.get(path)
        assert response.status_code == 200, path
        html = response.get_data(as_text=True)
        assert "enterprise_shell.css" in html
        assert "enterprise_shell.js" in html
        assert 'id="command-backdrop"' in html
        if path == "/":
            assert "dashboard_soc.css" in html
            assert "dashboard_soc.js" in html
            assert 'value="priority"' in html
            assert "Recorded alerts and investigation activity" in html
            assert 'data-chart="threat-activity"' in html
            assert "Timeline-derived investigation risk" not in html
        if path == "/cases":
            assert 'data-workspace-route="evidence"' in html
            assert "data-workspace-edit-shortcut" in html
            assert 'id="case-notes-help"' in html
        if path == "/admin":
            assert "identity_access.css" in html
            assert "User lifecycle" in html
            assert "Enterprise identity readiness" in html
            assert 'id="admin-role-form"' in html
        if path == "/settings":
            assert "ai_management.css" in html
            assert "Provider &amp; Model Management" in html
            assert 'id="ai-workload-form"' in html
            assert 'id="ai-prompt-form"' in html
            assert "Existing credentials are never displayed" in html
        if path == "/plugins":
            assert "plugin_management.css" in html
            assert 'id="plugin-config-form"' in html
            assert "Installed plugins" in html
            assert "Update availability is loading" in html
        for marker in markers:
            assert marker in html, (path, marker)


def test_user_navigation_excludes_administration_features() -> None:
    app = create_app("testing")
    response = app.test_client().get("/", headers={"X-CI-Role": "user", "X-CI-User": "ui-user"})
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "User management" not in html
    assert "Security center" not in html
    assert "Plugin Status" not in html
    for label in (
        "Investigation lifecycle",
        "Cases",
        "Evidence",
        "Timeline",
        "Reports",
        "AI investigation",
        "Profile &amp; activity",
        "Preferences",
        "Notifications",
    ):
        assert label in html
    assert 'aria-label="Breadcrumb"' in html
    assert 'data-cases="true"' in html
    assert 'data-reports="true"' in html
    assert 'data-evidence="true"' in html


def test_authentication_landing_preserves_contracts_and_enterprise_content() -> None:
    app = create_app("testing")
    client = app.test_client()
    modes = {
        "/login": ("Move from evidence", 'action="/login"', 'name="username"', 'name="password"', 'name="remember"'),
        "/register": (
            "Create your account",
            'action="/register"',
            'name="username"',
            'name="email"',
            'name="password"',
        ),
        "/forgot-password": ("Recover your access", 'action="/forgot-password"', 'name="email"'),
    }
    for path, markers in modes.items():
        response = client.get(path)
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "login.css" in html
        assert "login.js" in html
        assert 'name="csrf_token"' in html
        assert 'href="#auth-form"' in html
        assert "Built for the investigation lifecycle" in html
        assert "Role-aware access" in html
        for marker in markers:
            assert marker in html, (path, marker)


def test_authentication_entry_reflects_deployment_capabilities() -> None:
    app = create_app(
        "testing",
        {
            "REGISTRATION_ENABLED": False,
            "GOOGLE_CLIENT_ID": "",
            "GOOGLE_CLIENT_SECRET": "",
        },
    )
    html = app.test_client().get("/login").get_data(as_text=True)

    assert "Registration managed" in html
    assert 'href="/auth/google"' not in html

    recovery = app.test_client().get("/forgot-password").get_data(as_text=True)
    assert "Administrator-assisted recovery" in recovery
    assert "No reset email is sent" in recovery


def test_storage_workspace_preserves_enterprise_continuity_contract() -> None:
    html = create_app("testing").test_client().get("/settings#storage").get_data(as_text=True)

    assert "storage_management.css" in html
    assert "Storage, Backup &amp; Disaster Recovery" in html
    assert 'id="storage-create-backup"' in html
    assert 'id="storage-verify-integrity"' in html
    assert 'id="storage-policy-form"' in html
    assert 'id="storage-hold-form"' in html


def test_deployment_workspace_exposes_truthful_release_operations() -> None:
    html = create_app("testing").test_client().get("/admin").get_data(as_text=True)

    assert "deployment_management.css" in html
    assert "DevSecOps, CI/CD &amp; Deployment" in html
    assert 'id="deployment-verify"' in html
    assert 'id="deployment-pipelines"' in html
    assert 'id="deployment-failures"' in html
    assert 'id="deployment-releases"' in html
