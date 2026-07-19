"""Application-scoped logging configuration."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask


def register_logging(app: Flask) -> None:
    """Configure a rotating UTF-8 file handler for this Flask application."""
    log_directory = Path(app.config["LOGS_FOLDER"])
    log_directory.mkdir(parents=True, exist_ok=True)

    logger = app.logger
    logger.setLevel(_log_level(app.config.get("LOG_LEVEL", "INFO")))
    logger.propagate = False

    if any(getattr(handler, "_cyberinvestigator_handler", False) for handler in logger.handlers):
        return

    handler = RotatingFileHandler(
        log_directory / "cyberinvestigator.log",
        maxBytes=int(app.config.get("LOG_MAX_BYTES", 10_485_760)),
        backupCount=int(app.config.get("LOG_BACKUP_COUNT", 10)),
        encoding="utf-8",
    )
    handler._cyberinvestigator_handler = True  # type: ignore[attr-defined]
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s [%(process)d] %(message)s",
            "%Y-%m-%dT%H:%M:%S%z",
        )
    )
    logger.addHandler(handler)


def _log_level(value: object) -> int:
    """Convert a configured textual log level into a validated logging level."""
    if not isinstance(value, str):
        raise ValueError("LOG_LEVEL must be a logging level name.")
    level = logging.getLevelName(value.upper())
    if not isinstance(level, int):
        raise ValueError(f"Unsupported LOG_LEVEL {value!r}.")
    return level
