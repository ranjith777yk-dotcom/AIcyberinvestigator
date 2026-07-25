"""Application-scoped logging configuration."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask

from cyberinvestigator.infrastructure.observability import SecretRedactionFilter, StructuredJsonFormatter


def register_logging(app: Flask) -> None:
    """Configure a rotating UTF-8 file handler for this Flask application."""
    log_directory = Path(app.config["LOGS_FOLDER"])
    log_directory.mkdir(parents=True, exist_ok=True)

    log_path = log_directory / "cyberinvestigator.log"
    level = _log_level(app.config.get("LOG_LEVEL", "INFO"))
    package_logger = logging.getLogger("cyberinvestigator")
    loggers = (app.logger, package_logger)
    retired: set[logging.Handler] = set()
    for logger in loggers:
        logger.setLevel(level)
        logger.propagate = False
        for existing in list(logger.handlers):
            if not getattr(existing, "_cyberinvestigator_handler", False):
                continue
            logger.removeHandler(existing)
            retired.add(existing)
    for existing in retired:
        existing.close()

    handler = RotatingFileHandler(
        log_path,
        maxBytes=int(app.config.get("LOG_MAX_BYTES", 10_485_760)),
        backupCount=int(app.config.get("LOG_BACKUP_COUNT", 10)),
        encoding="utf-8",
    )
    handler._cyberinvestigator_handler = True  # type: ignore[attr-defined]
    secret_values = tuple(
        str(value)
        for key, value in app.config.items()
        if value and isinstance(value, str) and key.endswith(("_KEY", "_SECRET", "_PASSWORD", "_TOKEN"))
    )
    handler.addFilter(SecretRedactionFilter(secret_values))
    handler.setFormatter(StructuredJsonFormatter())
    for logger in loggers:
        logger.addHandler(handler)


def _log_level(value: object) -> int:
    """Convert a configured textual log level into a validated logging level."""
    if not isinstance(value, str):
        raise ValueError("LOG_LEVEL must be a logging level name.")
    level = logging.getLevelName(value.upper())
    if not isinstance(level, int):
        raise ValueError(f"Unsupported LOG_LEVEL {value!r}.")
    return level
