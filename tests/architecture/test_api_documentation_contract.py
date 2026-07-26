from __future__ import annotations

from pathlib import Path

from cyberinvestigator import create_app
from cyberinvestigator.api.v1.openapi import build_openapi_spec

ROOT = Path(__file__).resolve().parents[2]
METHODS = {"get", "post", "put", "patch", "delete"}


def test_openapi_operations_match_registered_visible_routes() -> None:
    app = create_app("testing")
    spec = build_openapi_spec(app, include_internal=True)
    documented = {
        (method.upper(), f"/api/v1{path}")
        for path, item in spec["paths"].items()
        for method in item
        if method in METHODS
    }
    registered = {
        (method, rule.rule)
        for rule in app.url_map.iter_rules()
        if rule.rule.startswith("/api/v1/")
        for method in set(rule.methods or ()) & {item.upper() for item in METHODS}
    }

    normalized_registered = {
        (
            method,
            path.replace("<uuid:", "{")
            .replace("<int:", "{")
            .replace("<string:", "{")
            .replace("<path:", "{")
            .replace("<", "{")
            .replace(">", "}"),
        )
        for method, path in registered
    }
    assert documented == normalized_registered


def test_openapi_contract_has_stable_ids_security_schemas_and_permissions() -> None:
    spec = build_openapi_spec(create_app("testing"), include_internal=True)
    operation_ids = []
    for path, item in spec["paths"].items():
        assert "<" not in path
        for method, operation in item.items():
            if method not in METHODS:
                continue
            operation_ids.append(operation["operationId"])
            assert operation["summary"]
            assert operation["responses"]["403"]["content"]["application/json"]["schema"]["$ref"]
            assert "x-required-permissions" in operation
    assert len(operation_ids) == len(set(operation_ids))
    assert spec["x-api-version"] == "v1"
    assert "CaseCreateRequest" in spec["components"]["schemas"]
    assert "sessionCookie" in spec["components"]["securitySchemes"]
    assert "csrfHeader" in spec["components"]["securitySchemes"]


def test_sdk_and_release_artifacts_are_truthfully_labeled() -> None:
    sdk_readme = (ROOT / "sdk" / "README.md").read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    webhook_adr = (ROOT / "docs" / "adr" / "0003-webhook-outbox-preparation.md").read_text(encoding="utf-8")

    assert "preview foundations" in sdk_readme
    assert "not published packages" in sdk_readme
    assert "Unreleased" in changelog
    assert "Do not expose subscription endpoints" in webhook_adr
