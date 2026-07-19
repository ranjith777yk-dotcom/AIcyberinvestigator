"""Safe, dependency-injected execution boundary for Java investigation plugins."""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from time import perf_counter
from typing import Mapping, Protocol
from uuid import uuid4

from cyberinvestigator.infrastructure.java_plugins.registry import (
    JavaPluginManifest,
    JavaPluginRegistry,
    JavaPluginRegistryError,
)
from cyberinvestigator.infrastructure.security.plugin_verification import (
    PluginVerificationError,
    sha256_file,
)


class JavaPluginRunnerError(RuntimeError):
    """Raised for invalid Java plugin transport configuration or output."""


class JavaPluginExecutionStatus(str, Enum):
    """Structured outcomes returned by a Java plugin transport."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True, slots=True, kw_only=True)
class PluginExecutionResult:
    """Structured result returned for every Java plugin execution attempt."""

    plugin_identifier: str
    status: JavaPluginExecutionStatus
    output: Mapping[str, object] | None
    logs: str
    exit_code: int | None
    error: str | None = None
    duration_ms: int | None = None


JavaPluginExecutionResult = PluginExecutionResult
"""Backward-compatible alias for :class:`PluginExecutionResult`."""


class JavaPluginTransport(Protocol):
    """Transport strategy for invoking a Java plugin without coupling the runner."""

    def execute(
        self, manifest: JavaPluginManifest, payload: Mapping[str, object], timeout_seconds: int
    ) -> PluginExecutionResult:
        """Invoke a plugin and return a structured, JSON-only result."""
        ...


class JarJavaPluginTransport:
    """Subprocess transport for a manifest-discovered Java JAR plugin."""

    def __init__(self, java_executable: str) -> None:
        """Configure the Java executable without embedding any plugin path."""
        self._java_executable = java_executable

    def execute(
        self, manifest: JavaPluginManifest, payload: Mapping[str, object], timeout_seconds: int
    ) -> PluginExecutionResult:
        """Run a JAR without a shell, passing JSON over standard input."""
        if manifest.jar_path is None:
            raise JavaPluginRunnerError("JAR transport requires a manifest jar_path.")
        request_id = str(uuid4())
        request_document = {
            "request_id": request_id,
            "requested_at": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        }
        if manifest.sha256:
            try:
                computed = sha256_file(manifest.jar_path)
            except PluginVerificationError as error:
                raise JavaPluginRunnerError(str(error)) from error
            if computed.lower() != manifest.sha256.strip().lower():
                raise JavaPluginRunnerError(f"Java plugin JAR SHA-256 mismatch for {manifest.identifier!r}.")

        started_at = perf_counter()
        try:
            completed = subprocess.run(
                [self._java_executable, "-jar", str(manifest.jar_path)],
                input=json.dumps(request_document),
                capture_output=True,
                check=False,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            return PluginExecutionResult(
                plugin_identifier=manifest.identifier,
                status=JavaPluginExecutionStatus.TIMED_OUT,
                output=None,
                logs=(error.stderr or "") if isinstance(error.stderr, str) else "",
                exit_code=None,
                error=f"Plugin exceeded the {timeout_seconds}-second timeout.",
                duration_ms=_elapsed_milliseconds(started_at),
            )
        except OSError as error:
            return PluginExecutionResult(
                plugin_identifier=manifest.identifier,
                status=JavaPluginExecutionStatus.FAILED,
                output=None,
                logs="",
                exit_code=None,
                error=str(error),
                duration_ms=_elapsed_milliseconds(started_at),
            )

        if completed.returncode != 0:
            return PluginExecutionResult(
                plugin_identifier=manifest.identifier,
                status=JavaPluginExecutionStatus.FAILED,
                output=None,
                logs=completed.stderr,
                exit_code=completed.returncode,
                error="Java plugin exited with a non-zero status.",
                duration_ms=_elapsed_milliseconds(started_at),
            )
        try:
            response = self._parse_output(completed.stdout, request_id)
        except JavaPluginRunnerError as error:
            return PluginExecutionResult(
                plugin_identifier=manifest.identifier,
                status=JavaPluginExecutionStatus.FAILED,
                output=None,
                logs=completed.stderr,
                exit_code=completed.returncode,
                error=str(error),
                duration_ms=_elapsed_milliseconds(started_at),
            )
        if response["status"] == "FAILED":
            return PluginExecutionResult(
                plugin_identifier=manifest.identifier,
                status=JavaPluginExecutionStatus.FAILED,
                output=None,
                logs=completed.stderr,
                exit_code=completed.returncode,
                error=_response_error_message(response),
                duration_ms=_elapsed_milliseconds(started_at),
            )
        return PluginExecutionResult(
            plugin_identifier=manifest.identifier,
            status=JavaPluginExecutionStatus.SUCCEEDED,
            output=response["payload"],
            logs=completed.stderr,
            exit_code=completed.returncode,
            duration_ms=_elapsed_milliseconds(started_at),
        )

    @staticmethod
    def _parse_output(stdout: str, request_id: str) -> Mapping[str, object]:
        """Validate one SDK-compliant JSON response object from standard output."""
        try:
            output = json.loads(stdout)
        except json.JSONDecodeError as error:
            raise JavaPluginRunnerError("Java plugin standard output must be valid JSON.") from error
        if not isinstance(output, dict):
            raise JavaPluginRunnerError("Java plugin JSON output must be an object.")
        response_request_id = output.get("requestId", output.get("request_id"))
        if response_request_id != request_id:
            raise JavaPluginRunnerError("Java plugin response request identifier does not match the request.")
        if output.get("status") not in {"SUCCEEDED", "FAILED"}:
            raise JavaPluginRunnerError("Java plugin response status must be SUCCEEDED or FAILED.")
        if not isinstance(output.get("payload"), dict):
            raise JavaPluginRunnerError("Java plugin response payload must be a JSON object.")
        if not isinstance(output.get("errors"), list):
            raise JavaPluginRunnerError("Java plugin response errors must be a JSON array.")
        return output


class RestJavaPluginTransport(Protocol):
    """Future REST transport contract for remote Java plugin services.

    No REST client is implemented yet; an adapter can satisfy this protocol and
    be injected into :class:`JavaPluginRunner` when service deployment is needed.
    """

    def execute(
        self, manifest: JavaPluginManifest, payload: Mapping[str, object], timeout_seconds: int
    ) -> PluginExecutionResult:
        """Send JSON to a declared REST plugin endpoint and return JSON output."""
        ...


class JavaPluginRunner:
    """Orchestrate registered Java plugins through injected transport strategies."""

    def __init__(
        self,
        registry: JavaPluginRegistry,
        transports: Mapping[str, JavaPluginTransport],
        timeout_seconds: int,
        logger: logging.Logger | None = None,
    ) -> None:
        """Create a runner with explicit registry, transport, and timeout dependencies."""
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero.")
        self._registry = registry
        self._transports = dict(transports)
        self._timeout_seconds = timeout_seconds
        self._logger = logger or logging.getLogger(__name__)

    def discover(self) -> tuple[JavaPluginManifest, ...]:
        """Discover Java plugins through the configured dynamic registry."""
        plugins = self._registry.discover()
        self._logger.info("Discovered %d Java plugin(s).", len(plugins))
        return plugins

    def run(self, plugin_identifier: str, payload: Mapping[str, object]) -> PluginExecutionResult:
        """Execute one discovered plugin and return a result for every outcome."""
        if not isinstance(payload, Mapping):
            return self._failure(plugin_identifier, "Java plugin payload must be a JSON object.")
        try:
            manifest = self._registry.get(plugin_identifier)
        except JavaPluginRegistryError as error:
            return self._failure(plugin_identifier, str(error))
        try:
            transport = self._transports[manifest.transport]
        except KeyError:
            return self._failure(
                plugin_identifier,
                f"No {manifest.transport!r} transport is configured for Java plugin execution.",
            )

        self._logger.info("Executing Java plugin %s through %s transport.", plugin_identifier, manifest.transport)
        try:
            result = transport.execute(manifest, payload, self._timeout_seconds)
        except JavaPluginRunnerError as error:
            result = self._failure(plugin_identifier, str(error))
        except Exception:
            self._logger.exception("Unexpected Java plugin transport failure for %s.", plugin_identifier)
            result = self._failure(plugin_identifier, "Java plugin execution failed unexpectedly.")

        log_level = logging.INFO if result.status is JavaPluginExecutionStatus.SUCCEEDED else logging.WARNING
        self._logger.log(
            log_level,
            "Java plugin %s completed with status %s in %s ms.",
            plugin_identifier,
            result.status.value,
            result.duration_ms if result.duration_ms is not None else "unknown",
        )
        return result

    @staticmethod
    def _failure(plugin_identifier: str, error: str) -> PluginExecutionResult:
        """Create a structured non-transport failure result."""
        return PluginExecutionResult(
            plugin_identifier=plugin_identifier,
            status=JavaPluginExecutionStatus.FAILED,
            output=None,
            logs="",
            exit_code=None,
            error=error,
        )


def _elapsed_milliseconds(started_at: float) -> int:
    """Return elapsed monotonic time rounded to milliseconds."""
    return round((perf_counter() - started_at) * 1_000)


def _response_error_message(response: Mapping[str, object]) -> str:
    """Return a safe diagnostic from an SDK error array without exposing raw logs."""
    errors = response["errors"]
    if not isinstance(errors, list) or not errors:
        return "Java plugin reported a failure without an error message."
    first_error = errors[0]
    if isinstance(first_error, Mapping) and isinstance(first_error.get("message"), str):
        return first_error["message"]
    return "Java plugin reported a failure with an invalid error response."
