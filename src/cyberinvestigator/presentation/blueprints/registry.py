"""Blueprint composition for the Flask application."""

from flask import Flask

from cyberinvestigator.api.v1.blueprint import api_v1_blueprint
from cyberinvestigator.presentation.blueprints.web import web_blueprint


def register_blueprints(app: Flask) -> None:
    """Register all HTTP blueprints exactly once with the application."""
    app.register_blueprint(web_blueprint)
    app.register_blueprint(api_v1_blueprint)
