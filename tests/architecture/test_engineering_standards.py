"""Executable repository-wide engineering policies."""

from __future__ import annotations

import ast
from pathlib import Path

from cyberinvestigator import create_app
from cyberinvestigator.infrastructure.security.web_security import (
    ENDPOINT_PERMISSIONS,
    PUBLIC_ENDPOINTS,
)

ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = ROOT / "src"
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def test_every_mutating_v1_endpoint_has_an_explicit_access_policy() -> None:
    """Prevent new command endpoints from silently bypassing central RBAC."""

    app = create_app("testing")
    uncovered: list[str] = []
    for rule in app.url_map.iter_rules():
        methods = set(rule.methods or ()) & MUTATING_METHODS
        if not rule.rule.startswith("/api/v1") or not methods:
            continue
        if rule.endpoint not in ENDPOINT_PERMISSIONS and rule.endpoint not in PUBLIC_ENDPOINTS:
            uncovered.append(f"{','.join(sorted(methods))} {rule.rule} ({rule.endpoint})")

    assert uncovered == [], "Mutating API routes require an explicit access policy:\n" + "\n".join(uncovered)


def test_application_code_does_not_write_to_stdout() -> None:
    """Operational output must use the configured, redactable logger."""

    violations: list[str] = []
    for path in SOURCE_ROOT.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print":
                violations.append(f"{path.relative_to(ROOT)}:{node.lineno}")

    assert violations == [], "Use application logging instead of print():\n" + "\n".join(violations)


def test_normative_engineering_documents_exist() -> None:
    required = (
        ROOT / "CONTRIBUTING.md",
        ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md",
        ROOT / "docs" / "engineering-standards.md",
    )

    assert [str(path.relative_to(ROOT)) for path in required if not path.is_file()] == []
