"""Flask application factory for CyberInvestigator AI."""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from flask import Flask
from sqlalchemy import select

from cyberinvestigator.config import CONFIG_BY_NAME, BaseConfig
from cyberinvestigator.domain.services.cybersecurity_ai import (
    ConversationMemoryStore,
    CybersecurityAnalysisEngine,
    InvestigationAssistant,
)
from cyberinvestigator.features import register_feature_modules
from cyberinvestigator.infrastructure.ai import build_ai_registry
from cyberinvestigator.infrastructure.ai_management import hydrate_ai_config
from cyberinvestigator.infrastructure.database.migrations import run_lightweight_migrations
from cyberinvestigator.infrastructure.database.models import Setting
from cyberinvestigator.infrastructure.database.registration import register_database
from cyberinvestigator.infrastructure.deployment_management import DeploymentInspector
from cyberinvestigator.infrastructure.jobs import InProcessJobDispatcher
from cyberinvestigator.infrastructure.logging import register_logging
from cyberinvestigator.infrastructure.observability import register_observability
from cyberinvestigator.infrastructure.plugins import PluginLoader, PluginRegistry
from cyberinvestigator.infrastructure.security.web_security import register_web_security
from cyberinvestigator.infrastructure.storage_management import LocalStorageManager
from cyberinvestigator.presentation.blueprints.registry import register_blueprints
from cyberinvestigator.presentation.errors import register_error_handlers


def _load_local_env() -> None:
    """Load simple KEY=VALUE pairs from .env without exposing or hardcoding secrets."""
    env_path = Path.cwd() / ".env"
    if not env_path.exists():
        return
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        text = line.strip()
        if not text or text.startswith("#") or "=" not in text:
            continue
        key, value = text.split("=", 1)
        key = key.strip()
        if not key or key in os.environ:
            continue
        cleaned = value.strip().strip('"').strip("'")
        os.environ[key] = cleaned


def create_app(config_name: str | None = None, config_overrides: dict[str, Any] | None = None) -> Flask:
    """Create and fully configure a CyberInvestigator Flask application.

    Args:
        config_name: One of ``development``, ``testing``, or ``production``.
            When omitted, ``CYBERINVESTIGATOR_ENV`` selects the profile.
        config_overrides: Explicit configuration overrides, primarily useful for
            isolated tests. Values are applied after the selected profile.

    Returns:
        A configured Flask application with extensions, persistence, logging,
        error handlers, and blueprints registered.

    Raises:
        ValueError: If the requested configuration profile is unsupported.
    """
    _load_local_env()
    profile_name = (config_name or os.getenv("CYBERINVESTIGATOR_ENV", "development")).lower()
    config_class = CONFIG_BY_NAME.get(profile_name)
    if config_class is None:
        supported_profiles = ", ".join(sorted(CONFIG_BY_NAME))
        raise ValueError(
            f"Unsupported configuration profile {profile_name!r}. " f"Supported profiles: {supported_profiles}."
        )

    package_root = Path(__file__).parent
    app = Flask(
        __name__,
        instance_relative_config=True,
        template_folder=str(package_root / "presentation" / "templates"),
        static_folder=str(package_root / "presentation" / "static"),
    )
    app.config.from_object(config_class)
    app.config["ENVIRONMENT"] = profile_name
    if config_overrides:
        app.config.update(config_overrides)

    _initialise_profile(config_class, app)
    _normalize_flask_config_types(app)

    register_extensions(app)
    register_database(app)
    run_lightweight_migrations(app)
    _register_storage_management(app)
    app.extensions["cyberinvestigator_deployment_inspector"] = DeploymentInspector(Path(app.config["PROJECT_ROOT"]))
    register_logging(app)
    register_observability(app)
    register_web_security(app)
    register_error_handlers(app)
    register_blueprints(app)
    _register_ai_runtime(app)
    register_feature_modules(app)
    _register_plugin_runtime(app)

    return app


def register_extensions(app: Flask) -> None:
    """Register framework extensions that do not own persistence concerns.

    Flask itself provides the extension registry.  This function provides a
    stable composition point for future, explicitly selected extensions without
    coupling the application factory to module-level singleton instances.
    """
    app.extensions.setdefault("cyberinvestigator", {})
    executor = app.extensions.setdefault(
        "cyberinvestigator_executor", ThreadPoolExecutor(max_workers=2, thread_name_prefix="ci-bg")
    )
    app.extensions.setdefault("cyberinvestigator_job_dispatcher", InProcessJobDispatcher(executor))
    app.extensions.setdefault("cyberinvestigator_jobs", {})


def _register_plugin_runtime(app: Flask) -> None:
    """Initialize the plugin registry and discovery loader from app configuration."""
    registry = PluginRegistry()
    app.extensions["cyberinvestigator_plugin_registry"] = registry
    if not bool(app.config.get("PLUGINS_ENABLED", True)):
        app.extensions["cyberinvestigator_plugin_loader"] = None
        return

    plugin_root = Path(app.config.get("PLUGINS_FOLDER", app.config.get("PLUGIN_ROOT", "plugins")))

    def permission_resolver(identifier: str) -> set[str]:
        setting = app.extensions["cyberinvestigator_database"].session.scalar(
            select(Setting).where(Setting.namespace == "plugin.permissions", Setting.key == identifier)
        )
        if setting is None:
            return set()
        try:
            values = json.loads(setting.value)
        except (TypeError, json.JSONDecodeError):
            return set()
        return {str(item) for item in values} if isinstance(values, list) else set()

    loader = PluginLoader(plugin_root, registry, permission_resolver)
    try:
        with app.app_context():
            loaded = loader.load_discovered()
    except Exception:
        app.logger.exception("Plugin discovery or startup validation failed.")
        app.extensions["cyberinvestigator_plugin_loader"] = loader
        app.extensions["cyberinvestigator_plugin_load_error"] = True
        return

    app.extensions["cyberinvestigator_plugin_loader"] = loader
    app.extensions["cyberinvestigator_plugin_loaded_count"] = len(loaded)
    app.extensions["cyberinvestigator_plugin_load_error"] = False


def _register_ai_runtime(app: Flask) -> None:
    """Initialize fallback-safe AI and cybersecurity analysis services."""
    analyzer = CybersecurityAnalysisEngine()
    memory = ConversationMemoryStore()
    with app.app_context():
        managed_config = hydrate_ai_config(app.config, app.extensions["cyberinvestigator_database"].session)
    app.extensions["cyberinvestigator_ai_registry"] = build_ai_registry(managed_config)
    app.extensions["cyberinvestigator_analysis_engine"] = analyzer
    app.extensions["cyberinvestigator_ai_memory"] = memory
    app.extensions["cyberinvestigator_investigation_assistant"] = InvestigationAssistant(analyzer, memory)


def _initialise_profile(config_class: type[BaseConfig], app: Flask) -> None:
    """Validate the profile and create runtime directories from effective config."""
    config_class._validate()
    for path_key in (
        "INSTANCE_PATH",
        "UPLOAD_FOLDER",
        "QUARANTINE_UPLOAD_FOLDER",
        "REPORTS_FOLDER",
        "BACKUP_ROOT",
        "LOGS_FOLDER",
    ):
        path = Path(app.config[path_key])
        path.mkdir(parents=True, exist_ok=True)


def _register_storage_management(app: Flask) -> None:
    """Register the local provider without changing evidence storage identifiers."""
    database = app.extensions["cyberinvestigator_database"]
    with app.app_context():
        engine = database.engine
        database_path = Path(engine.url.database) if engine.dialect.name == "sqlite" and engine.url.database else None
    manager = LocalStorageManager(
        instance_root=Path(app.config["INSTANCE_PATH"]),
        evidence_root=Path(app.config["QUARANTINE_UPLOAD_FOLDER"]),
        reports_root=Path(app.config["REPORTS_FOLDER"]),
        logs_root=Path(app.config["LOGS_FOLDER"]),
        backup_root=Path(app.config["BACKUP_ROOT"]),
        database_path=database_path,
    )
    app.extensions["cyberinvestigator_storage_manager"] = manager


def _normalize_flask_config_types(app: Flask) -> None:
    """Normalize Flask config values to only str/int/bool.

    Some config profiles intentionally keep internal values as ``pathlib.Path``.
    Flask's config is used across templates, JSON serialization, and other
    libraries, so we expose only JSON-safe primitive types.

    Backward compatibility: if a value is already a primitive, it is left
    unchanged.
    """

    def _to_str(value: object) -> object:
        # Keep only string-serializable primitives in app.config.
        if isinstance(value, Path):
            return str(value)
        return value

    for key, value in list(app.config.items()):
        app.config[key] = _to_str(value)

        # Normalize Path-like values that might slip through in overrides.
        if isinstance(app.config[key], Path):
            app.config[key] = str(app.config[key])
