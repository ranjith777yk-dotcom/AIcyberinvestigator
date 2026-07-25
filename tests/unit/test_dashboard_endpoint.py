from __future__ import annotations

from pathlib import Path

from flask import Flask

from cyberinvestigator import create_app
from cyberinvestigator.api.v1.blueprint import api_v1_blueprint
from cyberinvestigator.infrastructure.plugins import PluginRegistry


def test_dashboard_endpoint_returns_json_envelope() -> None:
    app = Flask(__name__)

    # Ensure ORM metadata is registered and tables exist for the test DB.
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from cyberinvestigator.infrastructure.database.base import Base
    from cyberinvestigator.infrastructure.database.models import Case, Evidence, TimelineEvent  # noqa: F401

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    db_session = Session(bind=engine)

    # attach a minimal extension to mimic app factory
    app.extensions["cyberinvestigator_database"] = type(
        "DB",
        (),
        {"session": db_session},
    )()

    app.config["AI_ENABLED"] = False
    app.config["PLUGINS_ENABLED"] = False

    app.register_blueprint(api_v1_blueprint)

    client = app.test_client()
    resp = client.get("/api/v1/dashboard")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert "cases_count" in payload
    assert payload["active_cases"] == []
    assert payload["ai_insights"] == []
    assert payload["lifecycle_progress"]["stages"] == {
        "case": False,
        "evidence": False,
        "timeline": False,
        "report": False,
    }


def test_plugin_endpoint_reports_registry_state() -> None:
    app = Flask(__name__)
    app.extensions["cyberinvestigator_plugin_registry"] = PluginRegistry()
    app.config["PLUGINS_ENABLED"] = True
    app.register_blueprint(api_v1_blueprint)

    client = app.test_client()
    resp = client.get("/api/v1/plugins")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["enabled"] is True
    assert payload["count"] == 0
    assert payload["plugins"] == []


def test_application_responses_include_security_headers() -> None:
    app = create_app("testing")
    response = app.test_client().get("/api/v1/dashboard")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_dashboard_client_does_not_fabricate_ai_confidence_or_refetch_cases() -> None:
    script_path = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "cyberinvestigator"
        / "presentation"
        / "static"
        / "js"
        / "dashboard_extras.js"
    )
    script = script_path.read_text(encoding="utf-8")

    assert "text: `${confidence}%`" not in script
    assert "Prioritize containment review" not in script
    assert 'fetchCases({ per_page: 100, sort: "opened_at"' not in script
    assert "No AI findings recorded" in script
