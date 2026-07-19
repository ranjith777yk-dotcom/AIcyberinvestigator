"""Unit tests for dynamic Java plugin discovery and execution boundaries."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from cyberinvestigator.infrastructure.java_plugins import (
    JarJavaPluginTransport,
    JavaPluginExecutionStatus,
    JavaPluginRegistry,
    JavaPluginRunner,
)


def _write_plugin_distribution(root: Path) -> None:
    """Create a minimal trusted JAR distribution fixture without executing a JAR."""
    plugin_directory = root / "pdf-analyzer"
    plugin_directory.mkdir()
    jar_bytes = b"jar fixture"
    (plugin_directory / "pdf-analyzer.jar").write_bytes(jar_bytes)
    sha256 = __import__("hashlib").sha256(jar_bytes).hexdigest()

    (plugin_directory / "cyberinvestigator-java-plugin.json").write_text(
        json.dumps(
            {
                "name": "pdf-analyzer",
                "version": "1.0.0",
                "author": "Test",
                "description": "Test Java plugin",
                "supported_artifact_types": ["pdf"],
                "supported_investigation_stages": ["triage"],
                "required_java_version": "21",
                "transport": "jar",
                "jar_file": "pdf-analyzer.jar",
                "sha256": sha256,
            }
        ),
        encoding="utf-8",
    )


def test_runner_discovers_and_executes_sdk_json_response(tmp_path: Path, monkeypatch) -> None:
    """The runner discovers a manifest, sends an envelope, and returns JSON payload."""
    _write_plugin_distribution(tmp_path)
    registry = JavaPluginRegistry(tmp_path)
    runner = JavaPluginRunner(
        registry,
        transports={"jar": JarJavaPluginTransport("java")},
        timeout_seconds=30,
    )

    def fake_run(*_args, **kwargs):  # type: ignore[no-untyped-def]
        request = json.loads(kwargs["input"])
        response = {
            "requestId": request["request_id"],
            "status": "SUCCEEDED",
            "completedAt": "2026-01-01T00:00:00Z",
            "payload": {"page_count": 3},
            "errors": [],
        }
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=json.dumps(response), stderr="plugin log")

    monkeypatch.setattr("cyberinvestigator.infrastructure.java_plugins.runner.subprocess.run", fake_run)

    discovered = runner.discover()
    result = runner.run("pdf-analyzer@1.0.0", {"pdf_path": "/evidence/file.pdf"})

    assert len(discovered) == 1

    assert result.status is JavaPluginExecutionStatus.SUCCEEDED
    assert result.output == {"page_count": 3}
    assert result.logs == "plugin log"


def test_runner_returns_structured_failure_for_invalid_plugin_response(tmp_path: Path, monkeypatch) -> None:
    """Malformed JAR output is converted into a failure result rather than raised."""
    _write_plugin_distribution(tmp_path)
    registry = JavaPluginRegistry(tmp_path)
    runner = JavaPluginRunner(
        registry,
        transports={"jar": JarJavaPluginTransport("java")},
        timeout_seconds=30,
    )
    runner.discover()

    monkeypatch.setattr(
        "cyberinvestigator.infrastructure.java_plugins.runner.subprocess.run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[], returncode=0, stdout="not-json", stderr="diagnostic"
        ),
    )

    result = runner.run("pdf-analyzer@1.0.0", {"pdf_path": "/evidence/file.pdf"})

    assert result.status is JavaPluginExecutionStatus.FAILED
    assert result.output is None
    assert result.error == "Java plugin standard output must be valid JSON."
