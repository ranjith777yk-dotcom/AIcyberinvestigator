"""Environment-aware configuration profiles for CyberInvestigator AI.

The module intentionally relies only on the Python standard library so it can be
loaded before Flask extensions are initialised.  Configuration values are exposed
as Flask-compatible class attributes and can be overridden through environment
variables.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import ClassVar

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - dependency is declared, fallback keeps imports safe.
    load_dotenv = None

if load_dotenv is not None:
    load_dotenv()


def _environment_value(name: str, default: str) -> str:
    """Return a stripped environment value, falling back when it is unset."""
    value = os.getenv(name)
    return value.strip() if value and value.strip() else default


def _boolean_value(name: str, default: bool) -> bool:
    """Read a strict boolean environment variable.

    Accepted true values are ``true``, ``1``, ``yes``, and ``on``; accepted false
    values are ``false``, ``0``, ``no``, and ``off``.  Invalid values fail fast so
    an unsafe deployment configuration is never silently accepted.
    """
    value = os.getenv(name)
    if value is None or not value.strip():
        return default

    normalised = value.strip().lower()
    if normalised in {"true", "1", "yes", "on"}:
        return True
    if normalised in {"false", "0", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean value, not {value!r}.")


def _positive_integer_value(name: str, default: int) -> int:
    """Read a positive integer environment variable with input validation."""
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        parsed = int(value)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer, not {value!r}.") from error
    if parsed <= 0:
        raise ValueError(f"{name} must be greater than zero.")
    return parsed


def _normalise_ai_model(model_name: str | None, *, provider_name: str | None = None) -> str:
    """Normalise AI model selection to a known-safe OpenAI-compatible default.

    This application does not implement provider-specific SDK wiring today. The
    goal here is to avoid passing unsupported model identifiers to downstream
    provider integrations, especially when ChatGPT/Codex-style model aliases are
    supplied in the environment. We conservatively fall back to a broadly
    supported model name rather than propagating a broken configuration.
    """
    if not model_name or not str(model_name).strip():
        return "gpt-4.1-mini"

    candidate = str(model_name).strip()
    lowered = candidate.lower()

    if provider_name and provider_name.lower() != "openai":
        return candidate

    supported_aliases = {
        "gpt-4o-mini",
        "gpt-4.1-mini",
        "gpt-4.1",
        "gpt-4o",
        "gpt-4-turbo",
        "gpt-4",
        "gpt-3.5-turbo",
    }

    if lowered in supported_aliases:
        return candidate

    if lowered.startswith("gpt-5") or lowered.startswith("o1") or lowered.startswith("o3"):
        return "gpt-4.1-mini"

    if "codex" in lowered or "chatgpt" in lowered:
        return "gpt-4.1-mini"

    return candidate


class BaseConfig:
    """Shared Flask configuration with secure, environment-driven defaults.

    Call :meth:`init_app` after ``app.config.from_object`` in the application
    factory.  It verifies the selected configuration and creates only the local
    runtime directories needed by the service.
    """

    ENVIRONMENT: ClassVar[str] = _environment_value("CYBERINVESTIGATOR_ENV", "development")
    PROJECT_ROOT: ClassVar[Path] = Path(_environment_value("CYBERINVESTIGATOR_PROJECT_ROOT", str(Path.cwd()))).resolve()
    INSTANCE_PATH: ClassVar[Path] = Path(
        _environment_value("CYBERINVESTIGATOR_INSTANCE_PATH", str(PROJECT_ROOT / "instance"))
    ).resolve()

    SECRET_KEY: ClassVar[str] = _environment_value("SECRET_KEY", secrets.token_urlsafe(48))
    SESSION_COOKIE_NAME: ClassVar[str] = _environment_value("SESSION_COOKIE_NAME", "cyberinvestigator_session")
    SESSION_COOKIE_HTTPONLY: ClassVar[bool] = True
    SESSION_COOKIE_SAMESITE: ClassVar[str] = _environment_value("SESSION_COOKIE_SAMESITE", "Lax")
    SESSION_COOKIE_SECURE: ClassVar[bool] = _boolean_value("SESSION_COOKIE_SECURE", False)
    SESSION_COOKIE_PARTITIONED: ClassVar[bool] = False
    PERMANENT_SESSION_LIFETIME: ClassVar[int] = _positive_integer_value("PERMANENT_SESSION_LIFETIME_SECONDS", 28_800)
    PREFERRED_URL_SCHEME: ClassVar[str] = _environment_value("PREFERRED_URL_SCHEME", "http")
    MAX_CONTENT_LENGTH: ClassVar[int] = _positive_integer_value("MAX_CONTENT_LENGTH_BYTES", 1_073_741_824)

    UPLOAD_ROOT: ClassVar[Path] = Path(_environment_value("UPLOAD_ROOT", str(INSTANCE_PATH / "uploads"))).resolve()
    UPLOAD_FOLDER: ClassVar[Path] = UPLOAD_ROOT / "incoming"
    QUARANTINE_UPLOAD_FOLDER: ClassVar[Path] = UPLOAD_ROOT / "quarantine"
    REPORTS_FOLDER: ClassVar[Path] = Path(
        _environment_value("REPORTS_FOLDER", str(INSTANCE_PATH / "reports"))
    ).resolve()
    LOGS_FOLDER: ClassVar[Path] = Path(_environment_value("LOGS_FOLDER", str(INSTANCE_PATH / "logs"))).resolve()
    LOG_LEVEL: ClassVar[str] = _environment_value("LOG_LEVEL", "INFO").upper()
    LOG_MAX_BYTES: ClassVar[int] = _positive_integer_value("LOG_MAX_BYTES", 10_485_760)
    LOG_BACKUP_COUNT: ClassVar[int] = _positive_integer_value("LOG_BACKUP_COUNT", 10)

    SQLALCHEMY_DATABASE_URI: ClassVar[str] = _environment_value(
        "DATABASE_URL", f"sqlite:///{(INSTANCE_PATH / 'cyberinvestigator.db').as_posix()}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: ClassVar[bool] = False
    DATABASE_AUTO_CREATE_SCHEMA: ClassVar[bool] = _boolean_value("DATABASE_AUTO_CREATE_SCHEMA", True)
    SQLALCHEMY_ENGINE_OPTIONS: ClassVar[dict[str, object]] = {
        "pool_pre_ping": True,
        "pool_recycle": _positive_integer_value("DATABASE_POOL_RECYCLE_SECONDS", 1_800),
    }

    AI_ENABLED: ClassVar[bool] = _boolean_value("AI_ENABLED", True)
    AI_PROVIDER: ClassVar[str] = _environment_value("AI_PROVIDER", "ollama")
    AI_MODEL: ClassVar[str] = _normalise_ai_model(
        _environment_value("AI_MODEL", _environment_value("OLLAMA_MODEL", "qwen3:8b")),
        provider_name=_environment_value("AI_PROVIDER", "ollama"),
    )
    AI_API_KEY: ClassVar[str | None] = os.getenv("OPENAI_API_KEY") or os.getenv("AI_API_KEY") or None
    AI_BASE_URL: ClassVar[str | None] = os.getenv("AI_BASE_URL") or None
    AI_TEMPERATURE: ClassVar[float] = float(_environment_value("AI_TEMPERATURE", "0.2"))
    AI_MAX_TOKENS: ClassVar[int] = _positive_integer_value("AI_MAX_TOKENS", 1200)
    AI_STREAMING: ClassVar[bool] = _boolean_value("AI_STREAMING", True)
    OLLAMA_ENDPOINT: ClassVar[str] = _environment_value("OLLAMA_ENDPOINT", "http://localhost:11434")
    OLLAMA_MODEL: ClassVar[str] = _environment_value("OLLAMA_MODEL", "qwen3:8b")
    OPENAI_MODEL: ClassVar[str] = _environment_value("OPENAI_MODEL", "gpt-4.1-mini")
    GEMINI_API_KEY: ClassVar[str | None] = os.getenv("GEMINI_API_KEY") or None
    GEMINI_MODEL: ClassVar[str] = _environment_value("GEMINI_MODEL", "gemini-1.5-flash")
    PERPLEXITY_API_KEY: ClassVar[str | None] = os.getenv("PERPLEXITY_API_KEY") or None
    PERPLEXITY_MODEL: ClassVar[str] = _environment_value("PERPLEXITY_MODEL", "sonar")
    AI_TIMEOUT_SECONDS: ClassVar[int] = _positive_integer_value("AI_TIMEOUT_SECONDS", 60)
    AI_MAX_RETRIES: ClassVar[int] = _positive_integer_value("AI_MAX_RETRIES", 3)

    RATE_LIMIT_REQUESTS: ClassVar[int] = _positive_integer_value("RATE_LIMIT_REQUESTS", 300)
    RATE_LIMIT_WINDOW_SECONDS: ClassVar[int] = _positive_integer_value("RATE_LIMIT_WINDOW_SECONDS", 60)
    DEFAULT_USER: ClassVar[str] = _environment_value("DEFAULT_USER", "investigator")
    DEFAULT_ADMIN_EMAIL: ClassVar[str] = _environment_value("DEFAULT_ADMIN_EMAIL", "investigator@example.local")
    DEFAULT_ADMIN_PASSWORD: ClassVar[str] = _environment_value("DEFAULT_ADMIN_PASSWORD", "ChangeMe!2026")
    USER_ROLES: ClassVar[str] = _environment_value("USER_ROLES", "investigator:admin")
    AUTH_REQUIRED: ClassVar[bool] = _boolean_value("AUTH_REQUIRED", True)
    REGISTRATION_ENABLED: ClassVar[bool] = _boolean_value("REGISTRATION_ENABLED", True)
    GOOGLE_CLIENT_ID: ClassVar[str | None] = os.getenv("GOOGLE_CLIENT_ID") or None
    GOOGLE_CLIENT_SECRET: ClassVar[str | None] = os.getenv("GOOGLE_CLIENT_SECRET") or None
    SESSION_TIMEOUT_SECONDS: ClassVar[int] = _positive_integer_value("SESSION_TIMEOUT_SECONDS", 28_800)
    MAX_FAILED_LOGINS: ClassVar[int] = _positive_integer_value("MAX_FAILED_LOGINS", 5)
    SECRET_REFERENCES: ClassVar[str] = _environment_value("SECRET_REFERENCES", "")
    HEALTHCHECK_TOKEN: ClassVar[str | None] = os.getenv("HEALTHCHECK_TOKEN") or None
    DASHBOARD_CACHE_SECONDS: ClassVar[int] = _positive_integer_value("DASHBOARD_CACHE_SECONDS", 5)

    PLUGINS_ENABLED: ClassVar[bool] = _boolean_value("PLUGINS_ENABLED", True)
    PLUGINS_FOLDER: ClassVar[Path] = Path(_environment_value("PLUGINS_FOLDER", str(PROJECT_ROOT / "plugins"))).resolve()
    PLUGIN_AUTO_DISCOVERY: ClassVar[bool] = _boolean_value("PLUGIN_AUTO_DISCOVERY", True)
    PLUGIN_SIGNATURE_VERIFICATION: ClassVar[bool] = _boolean_value("PLUGIN_SIGNATURE_VERIFICATION", True)
    JAVA_PLUGINS_FOLDER: ClassVar[Path] = Path(
        _environment_value("JAVA_PLUGINS_FOLDER", str(INSTANCE_PATH / "java_plugins"))
    ).resolve()
    JAVA_EXECUTABLE: ClassVar[str] = _environment_value("JAVA_EXECUTABLE", "java")
    JAVA_PLUGIN_TIMEOUT_SECONDS: ClassVar[int] = _positive_integer_value("JAVA_PLUGIN_TIMEOUT_SECONDS", 300)

    SECURITY_HEADERS_ENABLED: ClassVar[bool] = _boolean_value("SECURITY_HEADERS_ENABLED", True)
    CSRF_ENABLED: ClassVar[bool] = _boolean_value("CSRF_ENABLED", True)
    WTF_CSRF_ENABLED: ClassVar[bool] = CSRF_ENABLED
    PASSWORD_HASH_METHOD: ClassVar[str] = _environment_value("PASSWORD_HASH_METHOD", "scrypt")
    TRUSTED_HOSTS: ClassVar[list[str] | None] = [
        host.strip() for host in os.getenv("TRUSTED_HOSTS", "").split(",") if host.strip()
    ] or None

    @classmethod
    def init_app(cls) -> None:
        """Validate this profile and create required local runtime directories."""
        cls._validate()
        for directory in (
            cls.INSTANCE_PATH,
            cls.UPLOAD_FOLDER,
            cls.QUARANTINE_UPLOAD_FOLDER,
            cls.REPORTS_FOLDER,
            cls.LOGS_FOLDER,
        ):
            directory.mkdir(parents=True, exist_ok=True)

    @classmethod
    def _validate(cls) -> None:
        """Validate configuration invariants shared by every environment."""
        if cls.SESSION_COOKIE_SAMESITE not in {"Lax", "Strict", "None"}:
            raise ValueError("SESSION_COOKIE_SAMESITE must be Lax, Strict, or None.")
        if cls.SESSION_COOKIE_SAMESITE == "None" and not cls.SESSION_COOKIE_SECURE:
            raise ValueError("SESSION_COOKIE_SECURE must be enabled when SameSite is None.")
        # AI features must remain available in local fallback mode when a live
        # provider is not configured. Provider adapters report degraded status
        # instead of making application startup depend on an API key.


class DevelopmentConfig(BaseConfig):
    """Configuration for local development with Flask debugging enabled."""

    DEBUG: ClassVar[bool] = True
    SQLALCHEMY_ECHO: ClassVar[bool] = _boolean_value("SQLALCHEMY_ECHO", False)


class TestingConfig(BaseConfig):
    """Deterministic configuration for automated tests."""

    TESTING: ClassVar[bool] = True
    DEBUG: ClassVar[bool] = False
    WTF_CSRF_ENABLED: ClassVar[bool] = False
    SQLALCHEMY_DATABASE_URI: ClassVar[str] = _environment_value("TEST_DATABASE_URL", "sqlite+pysqlite:///:memory:")
    AI_ENABLED: ClassVar[bool] = _boolean_value("TEST_AI_ENABLED", False)
    PLUGINS_ENABLED: ClassVar[bool] = _boolean_value("TEST_PLUGINS_ENABLED", False)
    CSRF_ENABLED: ClassVar[bool] = False
    RATE_LIMIT_REQUESTS: ClassVar[int] = 10_000
    AUTH_REQUIRED: ClassVar[bool] = False


class ProductionConfig(BaseConfig):
    """Hardened configuration for deployed CyberInvestigator instances."""

    DEBUG: ClassVar[bool] = False
    DATABASE_AUTO_CREATE_SCHEMA: ClassVar[bool] = _boolean_value("DATABASE_AUTO_CREATE_SCHEMA", False)
    SESSION_COOKIE_SECURE: ClassVar[bool] = True
    PREFERRED_URL_SCHEME: ClassVar[str] = "https"

    @classmethod
    def _validate(cls) -> None:
        """Enforce production-only security and deployment requirements."""
        super()._validate()
        if not os.getenv("SECRET_KEY"):
            raise RuntimeError("SECRET_KEY must be explicitly set in production.")
        if not os.getenv("DATABASE_URL"):
            raise RuntimeError("DATABASE_URL must be explicitly set in production.")
        if not cls.TRUSTED_HOSTS:
            raise RuntimeError("TRUSTED_HOSTS must list one or more production hosts.")


CONFIG_BY_NAME: dict[str, type[BaseConfig]] = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}
"""Mapping from supported environment names to their configuration profiles."""
