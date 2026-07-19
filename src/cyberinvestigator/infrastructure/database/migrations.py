"""Small idempotent migration helpers for dependency-light deployments."""

from __future__ import annotations

from flask import Flask
from sqlalchemy import inspect, text

INDEXES = (
    ("ix_evidence_case_acquired", "evidence", "case_id, acquired_at"),
    ("ix_artifacts_content_hash", "artifacts", "content_hash"),
    ("ix_timeline_case_type", "timeline_events", "case_id, event_type"),
    ("ix_ai_reasoning_provider_model", "ai_reasoning", "provider, model"),
    ("ix_recommendations_case_status", "recommendations", "case_id, status"),
    ("ix_settings_namespace_updated", "settings", "namespace, updated_at"),
)

ADDITIVE_COLUMNS = (
    ("cases", "priority", "VARCHAR(32) NOT NULL DEFAULT 'medium'"),
    ("cases", "owner", "VARCHAR(255)"),
    ("cases", "tags", "TEXT"),
    ("cases", "notes", "TEXT"),
    ("cases", "relationships", "TEXT"),
    ("evidence", "analysis_report", "TEXT"),
    ("evidence", "analysis_summary", "TEXT"),
    ("evidence", "analysis_status", "VARCHAR(32) NOT NULL DEFAULT 'pending'"),
)


def run_lightweight_migrations(app: Flask) -> None:
    """Create additive indexes for existing databases.

    This intentionally avoids destructive schema rewrites. Constraint additions
    are represented in ORM metadata for new deployments; existing SQLite
    databases keep data compatibility and gain safe indexes.
    """

    database = app.extensions["cyberinvestigator_database"]
    with app.app_context():
        _migrate_users_username_scope(database)
        _repair_user_foreign_key_targets(database)
        for table_name, column_name, column_type in ADDITIVE_COLUMNS:
            if not _column_exists(database, table_name, column_name):
                database.session.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))
        for index_name, table_name, columns in INDEXES:
            database.session.execute(text(f"CREATE INDEX IF NOT EXISTS {index_name} ON {table_name} ({columns})"))
        database.session.commit()


def _column_exists(database, table_name: str, column_name: str) -> bool:
    """Return whether a column already exists in the configured database."""
    return any(column["name"] == column_name for column in inspect(database.engine).get_columns(table_name))


def _migrate_users_username_scope(database) -> None:
    """Replace legacy global username uniqueness with role-scoped uniqueness on SQLite."""
    if database.engine.dialect.name != "sqlite" or not inspect(database.engine).has_table("users"):
        return
    unique_username_indexes = []
    for index in database.session.execute(text("PRAGMA index_list(users)")).mappings():
        if not index.get("unique"):
            continue
        columns = [
            row["name"]
            for row in database.session.execute(text(f"PRAGMA index_info({index['name']})")).mappings()
            if row.get("name")
        ]
        if columns == ["username"]:
            unique_username_indexes.append(index["name"])
    if not unique_username_indexes:
        return
    database.session.execute(text("PRAGMA foreign_keys=OFF"))
    database.session.execute(text("PRAGMA legacy_alter_table=ON"))
    database.session.execute(text("ALTER TABLE users RENAME TO users_legacy_username_scope"))
    database.session.execute(
        text(
            """
            CREATE TABLE users (
                username VARCHAR(80) NOT NULL,
                email VARCHAR(255) NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role_id CHAR(32) NOT NULL,
                status VARCHAR(32) NOT NULL,
                failed_login_count INTEGER NOT NULL,
                locked_until DATETIME,
                last_login_at DATETIME,
                updated_at DATETIME NOT NULL,
                profile_image VARCHAR(1024),
                id CHAR(32) NOT NULL,
                created_at DATETIME NOT NULL,
                PRIMARY KEY (id),
                CONSTRAINT uq_users_username_role UNIQUE (username, role_id),
                CONSTRAINT uq_users_email UNIQUE (email),
                FOREIGN KEY(role_id) REFERENCES roles (id) ON DELETE RESTRICT
            )
            """
        )
    )
    database.session.execute(
        text(
            """
            INSERT INTO users (
                username, email, password_hash, role_id, status, failed_login_count, locked_until,
                last_login_at, updated_at, profile_image, id, created_at
            )
            SELECT
                username, email, password_hash, role_id, status, failed_login_count, locked_until,
                last_login_at, updated_at, profile_image, id, created_at
            FROM users_legacy_username_scope
            """
        )
    )
    database.session.execute(text("DROP TABLE users_legacy_username_scope"))
    database.session.execute(text("CREATE INDEX IF NOT EXISTS ix_users_username_role ON users (username, role_id)"))
    database.session.execute(text("CREATE INDEX IF NOT EXISTS ix_users_status_role ON users (status, role_id)"))
    database.session.execute(text("PRAGMA legacy_alter_table=OFF"))
    database.session.execute(text("PRAGMA foreign_keys=ON"))


def _repair_user_foreign_key_targets(database) -> None:
    """Repair SQLite foreign keys that were rewritten to the temporary users table name."""
    if database.engine.dialect.name != "sqlite":
        return
    legacy_target = "users_legacy_username_scope"
    repairs = {
        "user_sessions": _rebuild_user_sessions,
        "audit_logs": _rebuild_audit_logs,
        "notifications": _rebuild_notifications,
    }
    for table_name, rebuild in repairs.items():
        if not inspect(database.engine).has_table(table_name):
            continue
        targets = [
            row["table"] for row in database.session.execute(text(f"PRAGMA foreign_key_list({table_name})")).mappings()
        ]
        if legacy_target in targets:
            rebuild(database)


def _rebuild_user_sessions(database) -> None:
    database.session.execute(text("PRAGMA foreign_keys=OFF"))
    database.session.execute(text("ALTER TABLE user_sessions RENAME TO user_sessions_repair"))
    database.session.execute(
        text(
            """
            CREATE TABLE user_sessions (
                user_id CHAR(32) NOT NULL,
                session_token_hash VARCHAR(128) NOT NULL,
                ip_address VARCHAR(128),
                user_agent TEXT,
                active BOOLEAN NOT NULL,
                expires_at DATETIME NOT NULL,
                last_seen_at DATETIME NOT NULL,
                id CHAR(32) NOT NULL,
                created_at DATETIME NOT NULL,
                PRIMARY KEY (id),
                UNIQUE (session_token_hash),
                FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
            )
            """
        )
    )
    database.session.execute(
        text(
            """
            INSERT INTO user_sessions (
                user_id, session_token_hash, ip_address, user_agent, active, expires_at,
                last_seen_at, id, created_at
            )
            SELECT user_id, session_token_hash, ip_address, user_agent, active, expires_at,
                last_seen_at, id, created_at
            FROM user_sessions_repair
            """
        )
    )
    database.session.execute(text("DROP TABLE user_sessions_repair"))
    database.session.execute(
        text("CREATE INDEX IF NOT EXISTS ix_user_sessions_user_active ON user_sessions (user_id, active)")
    )
    database.session.execute(text("PRAGMA foreign_keys=ON"))


def _rebuild_audit_logs(database) -> None:
    database.session.execute(text("PRAGMA foreign_keys=OFF"))
    database.session.execute(text("ALTER TABLE audit_logs RENAME TO audit_logs_repair"))
    database.session.execute(
        text(
            """
            CREATE TABLE audit_logs (
                user_id CHAR(32),
                username VARCHAR(80),
                role VARCHAR(64),
                action VARCHAR(128) NOT NULL,
                result VARCHAR(32) NOT NULL,
                ip_address VARCHAR(128),
                user_agent TEXT,
                affected_object VARCHAR(255),
                reason TEXT,
                id CHAR(32) NOT NULL,
                created_at DATETIME NOT NULL,
                PRIMARY KEY (id),
                FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE SET NULL
            )
            """
        )
    )
    database.session.execute(
        text(
            """
            INSERT INTO audit_logs (
                user_id, username, role, action, result, ip_address, user_agent,
                affected_object, reason, id, created_at
            )
            SELECT user_id, username, role, action, result, ip_address, user_agent,
                affected_object, reason, id, created_at
            FROM audit_logs_repair
            """
        )
    )
    database.session.execute(text("DROP TABLE audit_logs_repair"))
    database.session.execute(
        text("CREATE INDEX IF NOT EXISTS ix_audit_logs_created_action ON audit_logs (created_at, action)")
    )
    database.session.execute(
        text("CREATE INDEX IF NOT EXISTS ix_audit_logs_user_created ON audit_logs (user_id, created_at)")
    )
    database.session.execute(text("PRAGMA foreign_keys=ON"))


def _rebuild_notifications(database) -> None:
    database.session.execute(text("PRAGMA foreign_keys=OFF"))
    database.session.execute(text("ALTER TABLE notifications RENAME TO notifications_repair"))
    database.session.execute(
        text(
            """
            CREATE TABLE notifications (
                user_id CHAR(32),
                title VARCHAR(255) NOT NULL,
                message TEXT NOT NULL,
                category VARCHAR(64) NOT NULL,
                priority VARCHAR(32) NOT NULL,
                read BOOLEAN NOT NULL,
                archived BOOLEAN NOT NULL,
                pinned BOOLEAN NOT NULL,
                id CHAR(32) NOT NULL,
                created_at DATETIME NOT NULL,
                PRIMARY KEY (id),
                FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
            )
            """
        )
    )
    database.session.execute(
        text(
            """
            INSERT INTO notifications (
                user_id, title, message, category, priority, read, archived, pinned, id, created_at
            )
            SELECT user_id, title, message, category, priority, read, archived, pinned, id, created_at
            FROM notifications_repair
            """
        )
    )
    database.session.execute(text("DROP TABLE notifications_repair"))
    database.session.execute(
        text("CREATE INDEX IF NOT EXISTS ix_notifications_user_read ON notifications (user_id, read)")
    )
    database.session.execute(text("PRAGMA foreign_keys=ON"))
