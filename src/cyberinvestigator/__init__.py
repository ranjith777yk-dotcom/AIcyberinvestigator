"""CyberInvestigator AI application package."""

from typing import Any

from flask import Flask


def create_app(config_name: str | None = None, config_overrides: dict[str, Any] | None = None) -> Flask:
    """Create the configured Flask application without eager extension imports."""
    from cyberinvestigator.app import create_app as application_factory

    return application_factory(config_name, config_overrides)


__all__ = ["create_app"]
