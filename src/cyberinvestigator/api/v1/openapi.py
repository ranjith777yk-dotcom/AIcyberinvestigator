"""OpenAPI generation derived from registered v1 routes and access policies."""

from __future__ import annotations

import re
from dataclasses import MISSING, fields, is_dataclass
from datetime import UTC, datetime
from types import UnionType
from typing import Any, Union, get_args, get_origin, get_type_hints

from flask import Flask

from cyberinvestigator.api.v1 import schemas
from cyberinvestigator.infrastructure.security.web_security import ENDPOINT_PERMISSIONS, PUBLIC_ENDPOINTS

_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
_PATH_PARAMETER = re.compile(r"<(?:(?:uuid|int|string|path):)?([^>]+)>")
_ADMIN_PERMISSIONS = {
    "admin.access",
    "settings.manage",
    "users.manage",
    "security.monitor",
    "storage.manage",
    "deployments.manage",
    "governance.manage",
    "plugins.manage",
}


def build_openapi_spec(app: Flask, *, include_internal: bool = False) -> dict[str, Any]:
    """Generate an access-aware OpenAPI contract from the registered route map."""
    spec: dict[str, Any] = {
        "openapi": "3.0.3",
        "info": {
            "title": "CyberInvestigator API",
            "version": "1.0.0",
            "description": (
                "Stable version 1 REST API. Operations are generated from the running application route map; "
                "administrative operations are included only for authorized administrators."
            ),
        },
        "servers": [{"url": "/api/v1", "description": "Current deployment"}],
        "tags": [],
        "paths": {},
        "components": {
            "securitySchemes": {
                "sessionCookie": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": str(app.config.get("SESSION_COOKIE_NAME", "cyberinvestigator_session")),
                    "description": "Secure server-managed browser session.",
                },
                "csrfHeader": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-CSRF-Token",
                    "description": "Required for state-changing session-authenticated requests when CSRF is enabled.",
                },
            },
            "schemas": _component_schemas(),
        },
        "security": [{"sessionCookie": []}],
    }
    tags: set[str] = set()
    for rule in sorted(app.url_map.iter_rules(), key=lambda item: item.rule):
        if not rule.rule.startswith("/api/v1/"):
            continue
        methods = sorted(set(rule.methods or ()) & _METHODS)
        if not methods or (not include_internal and _is_internal(rule.endpoint)):
            continue
        path = _openapi_path(rule.rule.removeprefix("/api/v1"))
        tag = _tag_for(path)
        tags.add(tag)
        path_item: dict[str, Any] = spec["paths"].setdefault(path, {})
        for method in methods:
            permissions = list(ENDPOINT_PERMISSIONS.get(rule.endpoint, ()))
            operation_id = rule.endpoint.removeprefix("api_v1.").replace(".", "_")
            if len(methods) > 1:
                operation_id = f"{operation_id}_{method.lower()}"
            operation: dict[str, Any] = {
                "operationId": operation_id,
                "summary": _summary(rule.endpoint),
                "tags": [tag],
                "responses": _responses(method),
                "x-required-permissions": permissions,
                "x-visibility": "internal" if _is_internal(rule.endpoint) else "authenticated",
            }
            parameters = _parameters(rule.rule)
            if parameters:
                operation["parameters"] = parameters
            if method in {"POST", "PUT", "PATCH", "DELETE"}:
                operation["security"] = [{"sessionCookie": [], "csrfHeader": []}]
                if method != "DELETE":
                    operation["requestBody"] = {
                        "required": False,
                        "content": {"application/json": {"schema": {"type": "object", "additionalProperties": True}}},
                    }
            elif rule.endpoint in PUBLIC_ENDPOINTS:
                operation["security"] = []
                operation["x-visibility"] = "public"
            path_item[method.lower()] = operation
    spec["tags"] = [{"name": tag} for tag in sorted(tags)]
    spec["x-api-version"] = "v1"
    spec["x-generated-at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    spec["x-generation-source"] = "registered Flask routes and centralized endpoint permissions"
    return spec


def _openapi_path(path: str) -> str:
    return _PATH_PARAMETER.sub(lambda match: "{" + match.group(1) + "}", path)


def _parameters(path: str) -> list[dict[str, object]]:
    parameters = []
    for converter, name in re.findall(r"<(?:(uuid|int|string|path):)?([^>]+)>", path):
        schema: dict[str, object] = {"type": "integer"} if converter == "int" else {"type": "string"}
        if converter == "uuid":
            schema["format"] = "uuid"
        parameters.append({"name": name, "in": "path", "required": True, "schema": schema})
    return parameters


def _is_internal(endpoint: str) -> bool:
    return bool(set(ENDPOINT_PERMISSIONS.get(endpoint, ())) & _ADMIN_PERMISSIONS)


def _tag_for(path: str) -> str:
    first = next((part for part in path.split("/") if part), "platform")
    return {"health": "Health", "monitoring": "Monitoring", "admin": "Administration"}.get(
        first, first.replace("-", " ").title()
    )


def _summary(endpoint: str) -> str:
    return endpoint.removeprefix("api_v1.").replace("_", " ").replace(".", " ").strip().capitalize()


def _responses(method: str) -> dict[str, object]:
    success = "201" if method == "POST" else "200"
    return {
        success: {"description": "Successful response"},
        "400": {"description": "Invalid request", "content": _error_content()},
        "401": {"description": "Authentication required", "content": _error_content()},
        "403": {"description": "Insufficient permission", "content": _error_content()},
        "404": {"description": "Resource not found", "content": _error_content()},
        "409": {"description": "State conflict", "content": _error_content()},
        "429": {"description": "Rate limit exceeded", "content": _error_content()},
        "500": {"description": "Internal error with a safe error identifier", "content": _error_content()},
    }


def _error_content() -> dict[str, object]:
    return {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorEnvelope"}}}


def _component_schemas() -> dict[str, object]:
    result: dict[str, object] = {
        "ErrorEnvelope": {
            "type": "object",
            "properties": {"error": {"oneOf": [{"type": "string"}, {"type": "object"}]}},
            "required": ["error"],
        }
    }
    for name in dir(schemas):
        model = getattr(schemas, name)
        if not isinstance(model, type) or not is_dataclass(model):
            continue
        hints = get_type_hints(model)
        properties = {field.name: _json_schema(hints.get(field.name, Any)) for field in fields(model)}
        required = [
            field.name
            for field in fields(model)
            if field.default is MISSING
            and field.default_factory is MISSING
            and not _nullable(hints.get(field.name, Any))
        ]
        document: dict[str, object] = {"type": "object", "properties": properties}
        if required:
            document["required"] = required
        result[name] = document
    return result


def _nullable(annotation: object) -> bool:
    return type(None) in get_args(annotation)


def _json_schema(annotation: object) -> dict[str, object]:
    origin = get_origin(annotation)
    args = get_args(annotation)
    if origin in (Union, UnionType):
        non_null = [item for item in args if item is not type(None)]
        schema = (
            _json_schema(non_null[0]) if len(non_null) == 1 else {"oneOf": [_json_schema(item) for item in non_null]}
        )
        if len(non_null) != len(args):
            schema["nullable"] = True
        return schema
    if origin is list:
        return {"type": "array", "items": _json_schema(args[0] if args else Any)}
    if annotation is str:
        return {"type": "string"}
    if annotation is int:
        return {"type": "integer"}
    if annotation is float:
        return {"type": "number"}
    if annotation is bool:
        return {"type": "boolean"}
    if getattr(annotation, "__name__", "") == "UUID":
        return {"type": "string", "format": "uuid"}
    if getattr(annotation, "__name__", "") == "datetime":
        return {"type": "string", "format": "date-time"}
    return {"type": "object", "additionalProperties": True}
