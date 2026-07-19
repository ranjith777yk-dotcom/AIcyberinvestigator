"""Minimal OpenAPI generator for API v1.

This project does not currently have a dedicated OpenAPI framework.
We generate a static-but-derived OpenAPI document using registered routes
and a small amount of schema metadata.

The goal is to keep runtime dependencies low while still providing a usable
OpenAPI output for clients and tests.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from flask import Flask


def build_openapi_spec(app: Flask) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "openapi": "3.0.3",
        "info": {
            "title": "CyberInvestigator API",
            "version": "1.0.0",
            "description": "Versioned REST API for core investigation services.",
        },
        "paths": {},
    }

    for rule in app.url_map.iter_rules():
        if not rule.rule.startswith("/api/v1/"):
            continue
        methods = sorted(m for m in rule.methods or [] if m in {"GET", "POST", "PUT", "PATCH", "DELETE"})
        if not methods:
            continue

        path_item: dict[str, Any] = spec["paths"].setdefault(rule.rule, {})
        for method in methods:
            # Provide a minimal operation shell. Detailed schema annotations are
            # handled by Pydantic in future iterations.
            path_item[method.lower()] = {
                "summary": f"{method} {rule.rule}",
                "responses": {
                    "200": {"description": "OK"},
                    "400": {"description": "Bad Request"},
                    "404": {"description": "Not Found"},
                    "500": {"description": "Internal Server Error"},
                },
            }

    spec["x-generated-at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return spec
