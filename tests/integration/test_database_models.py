"""Integration tests for the SQLAlchemy persistence schema."""

import pytest

sqlalchemy = pytest.importorskip("sqlalchemy", reason="SQLAlchemy is required for schema integration tests.")

from cyberinvestigator.infrastructure.database.base import Base  # noqa: E402
from cyberinvestigator.infrastructure.database.models import (  # noqa: E402,F401
    AIReasoning,
    Artifact,
    Case,
    Evidence,
    InvestigationState,
    Plugin,
    PluginExecution,
    Recommendation,
    Report,
    Setting,
    TimelineEvent,
)


def test_sqlite_configuration_enforces_foreign_keys() -> None:
    """The SQLite adapter enables foreign-key integrity rather than silently ignoring it."""
    from cyberinvestigator import create_app

    app = create_app("testing")
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        enabled = database.session.execute(sqlalchemy.text("PRAGMA foreign_keys")).scalar_one()

    assert enabled == 1


def test_application_factory_initializes_database_schema() -> None:
    """A freshly created app can serve database-backed endpoints immediately."""
    from cyberinvestigator import create_app

    app = create_app("testing")
    client = app.test_client()

    response = client.get("/api/v1/dashboard")

    assert response.status_code == 200
    assert response.get_json()["cases_count"] == 0


def test_database_metadata_contains_required_normalized_tables() -> None:
    """All core entities are registered in the shared declarative metadata."""
    required_tables = {
        "cases",
        "evidence",
        "artifacts",
        "timeline_events",
        "investigation_states",
        "plugins",
        "plugin_executions",
        "ai_reasoning",
        "recommendations",
        "reports",
        "settings",
    }

    assert required_tables <= set(Base.metadata.tables)


def test_evidence_is_normalized_through_case_foreign_key() -> None:
    """Evidence references its owning case rather than duplicating case metadata."""
    evidence_table = Base.metadata.tables["evidence"]
    case_foreign_keys = {foreign_key.target_fullname for foreign_key in evidence_table.c.case_id.foreign_keys}

    assert case_foreign_keys == {"cases.id"}
