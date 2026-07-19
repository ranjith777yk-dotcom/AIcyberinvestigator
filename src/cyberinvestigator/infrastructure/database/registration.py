"""Per-application SQLAlchemy registration."""

from __future__ import annotations

from typing import Any

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event

from cyberinvestigator.infrastructure.database.base import Base


def register_database(app: Flask) -> SQLAlchemy:
    """Create and attach a SQLAlchemy extension to one Flask application.

    The extension is deliberately instantiated here rather than as a module
    singleton, preventing configuration or engine state from leaking between
    application instances and test suites.
    """
    database = SQLAlchemy(model_class=Base)
    database.init_app(app)
    with app.app_context():
        import cyberinvestigator.infrastructure.database.models  # noqa: F401

        engine = database.engine
        if engine.dialect.name == "sqlite":
            event.listen(engine, "connect", _enable_sqlite_foreign_keys)
        if bool(app.config.get("DATABASE_AUTO_CREATE_SCHEMA", True)):
            database.create_all()
    app.extensions["cyberinvestigator_database"] = database
    return database


def _enable_sqlite_foreign_keys(dbapi_connection: Any, _connection_record: Any) -> None:
    """Enable SQLite foreign-key enforcement for every newly opened connection."""
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()
