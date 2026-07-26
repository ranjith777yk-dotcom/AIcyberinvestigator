"""Repository-level assertions for secure and repeatable delivery contracts."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_ci_contains_quality_security_and_container_gates() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    for marker in (
        "python -m ruff check .",
        "python -m ruff format --check src tests",
        "python -m pytest",
        "python -m pip_audit",
        "python -m bandit",
        "github/codeql-action/analyze@v3",
        "docker/build-push-action@v6",
    ):
        assert marker in workflow


def test_release_pipeline_uses_protected_delivery_and_provenance() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert "environment:" in workflow
    assert "packages: write" in workflow
    assert "attestations: write" in workflow
    assert "actions/attest-build-provenance@v2" in workflow
    assert "No deployment target is configured" in workflow


def test_container_runs_unprivileged_with_readiness_healthcheck() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    assert "AS builder" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "/api/v1/health/ready" in dockerfile
    assert "read_only: true" in compose
    assert "no-new-privileges:true" in compose
    assert "cap_drop:" in compose
    assert "${POSTGRES_PASSWORD:?" in compose
    assert "STOPSIGNAL SIGTERM" in dockerfile
    assert "gunicorn.conf.py" in dockerfile
    assert "stop_grace_period:" in compose


def test_secrets_are_excluded_from_container_context() -> None:
    ignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()

    assert ".env" in ignore
    assert ".env.*" in ignore
