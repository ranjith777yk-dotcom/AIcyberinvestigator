from __future__ import annotations

from flask import render_template_string

from cyberinvestigator import create_app


def test_design_system_assets_are_loaded_by_public_and_authenticated_shells() -> None:
    app = create_app("testing")
    client = app.test_client()
    for path in ("/", "/login", "/register", "/forgot-password"):
        response = client.get(path)
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "design_system.css" in html
        assert "responsive.css" in html
        if path == "/":
            assert "responsive.js" in html


def test_design_system_macros_render_safe_accessible_primitives() -> None:
    app = create_app("testing")
    with app.test_request_context():
        html = render_template_string(
            """
            {% import "components/ui.html" as ui %}
            {{ ui.button("Analyze", "primary", "search", id="analyze") }}
            {{ ui.status("Needs review", "warning") }}
            {{ ui.empty_state("No evidence", "Add an artifact.", "inbox") }}
            {{ ui.error_state("Unavailable", "Try again later.", "retry") }}
            {{ ui.skeleton(2, "Loading evidence") }}
            """
        )
    assert 'class="ci-button ci-button--primary"' in html
    assert 'id="analyze"' in html
    assert "ci-status--warning" in html
    assert "ci-state--empty" in html
    assert 'role="alert"' in html
    assert 'role="status"' in html
    assert 'aria-label="Loading evidence"' in html
