"""Direct PowerShell entry point for the CyberInvestigator Flask application."""

from __future__ import annotations

import os

from cyberinvestigator import create_app

app = create_app()
"""WSGI application object for Gunicorn and other production servers."""


def main() -> None:
    """Create and run the configured CyberInvestigator Flask application."""
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5000"))
    os.environ.setdefault("FLASK_SKIP_DOTENV", "1")
    app.run(host=host, port=port, debug=bool(app.config["DEBUG"]))


if __name__ == "__main__":
    main()
