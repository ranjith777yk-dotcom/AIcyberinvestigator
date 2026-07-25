from __future__ import annotations

import ast
from pathlib import Path

SOURCE_ROOT = Path(__file__).parents[2] / "src" / "cyberinvestigator"


def _imports_below(package: str) -> list[tuple[Path, str]]:
    imports: list[tuple[Path, str]] = []
    for source_file in (SOURCE_ROOT / package).rglob("*.py"):
        tree = ast.parse(source_file.read_text(encoding="utf-8"), filename=str(source_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend((source_file, alias.name) for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.append((source_file, node.module))
    return imports


def _matches_forbidden(module: str, forbidden: tuple[str, ...]) -> bool:
    return any(module == prefix or module.startswith(f"{prefix}.") for prefix in forbidden)


def test_domain_has_no_transport_or_framework_dependencies() -> None:
    forbidden = ("flask", "cyberinvestigator.api", "cyberinvestigator.presentation")
    violations = [
        f"{path.relative_to(SOURCE_ROOT)} imports {module}"
        for path, module in _imports_below("domain")
        if _matches_forbidden(module, forbidden)
    ]
    assert not violations, "\n".join(violations)


def test_application_has_no_transport_dependencies() -> None:
    forbidden = ("flask", "cyberinvestigator.api", "cyberinvestigator.presentation")
    violations = [
        f"{path.relative_to(SOURCE_ROOT)} imports {module}"
        for path, module in _imports_below("application")
        if _matches_forbidden(module, forbidden)
    ]
    assert not violations, "\n".join(violations)
