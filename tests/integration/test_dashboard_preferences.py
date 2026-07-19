"""Server-rendered checks for dashboard controls backed by client preferences."""

from __future__ import annotations

from cyberinvestigator import create_app


def test_dashboard_exposes_visible_theme_and_notification_controls() -> None:
    """The upper-right bar exposes discoverable appearance and notification controls."""
    app = create_app("testing")
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'id="theme-toggle-top"' in body
    assert 'id="theme-toggle-profile"' in body
    assert 'id="notification-button"' in body
    assert 'id="mark-notifications-read"' in body


def test_settings_exposes_persistent_local_appearance_preference() -> None:
    """The Settings page includes the dark-mode control controlled by dashboard JavaScript."""
    app = create_app("testing")

    response = app.test_client().get("/settings")

    assert response.status_code == 200
    assert 'id="theme-toggle"' in response.get_data(as_text=True)
