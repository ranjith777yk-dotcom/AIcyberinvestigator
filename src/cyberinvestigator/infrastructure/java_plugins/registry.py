"""Dynamic discovery and validation of Java plugin manifests."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any, Literal

JavaPluginTransport = Literal["jar", "rest"]
"""Transport modes supported by the Python-to-Java integration boundary."""


class JavaPluginRegistryError(ValueError):
    """Raised when a Java plugin manifest is invalid or conflicts with the registry."""


@dataclass(frozen=True, slots=True, kw_only=True)
class JavaPluginManifest:
    """Validated metadata and location for one dynamically discovered Java plugin."""

    name: str
    version: str
    author: str
    description: str
    supported_artifact_types: tuple[str, ...]
    supported_investigation_stages: tuple[str, ...]
    required_java_version: str
    transport: JavaPluginTransport
    manifest_path: Path
    jar_path: Path | None = None
    rest_endpoint: str | None = None
    sha256: str | None = None

    @property
    def identifier(self) -> str:
        """Return the stable dynamic identifier for the declared plugin version."""
        return f"{self.name}@{self.version}"


class JavaPluginRegistry:
    """Instance-scoped registry that discovers Java plugins without fixed paths."""

    manifest_filename = "cyberinvestigator-java-plugin.json"

    def __init__(self, plugin_root: Path) -> None:
        """Create an empty registry constrained to one configured plugin root."""
        self._plugin_root = plugin_root.resolve()
        self._plugins: dict[str, JavaPluginManifest] = {}
        self._lock = RLock()

    def discover(self) -> tuple[JavaPluginManifest, ...]:
        """Discover and register every valid manifest below the configured root."""
        if not self._plugin_root.exists():
            return ()
        if not self._plugin_root.is_dir():
            raise JavaPluginRegistryError("Java plugin root must be a directory.")

        discovered = tuple(
            self._read_manifest(path) for path in sorted(self._plugin_root.rglob(self.manifest_filename))
        )
        with self._lock:
            self._plugins.clear()
            for plugin in discovered:
                if plugin.identifier in self._plugins:
                    raise JavaPluginRegistryError(f"Duplicate Java plugin identifier {plugin.identifier!r}.")
                self._plugins[plugin.identifier] = plugin
        return discovered

    def get(self, identifier: str) -> JavaPluginManifest:
        """Return a discovered manifest by its stable name-and-version identifier."""
        with self._lock:
            try:
                return self._plugins[identifier]
            except KeyError as error:
                raise JavaPluginRegistryError(f"Java plugin {identifier!r} is not registered.") from error

    def list(self) -> tuple[JavaPluginManifest, ...]:
        """Return currently discovered Java plugin metadata in stable discovery order."""
        with self._lock:
            return tuple(self._plugins.values())

    def _read_manifest(self, manifest_path: Path) -> JavaPluginManifest:
        """Read and validate one JSON manifest without loading or executing a JAR."""
        try:
            document = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise JavaPluginRegistryError(f"Invalid Java plugin manifest: {manifest_path}") from error
        if not isinstance(document, dict):
            raise JavaPluginRegistryError("Java plugin manifest must contain a JSON object.")

        transport = self._required_string(document, "transport")
        if transport not in {"jar", "rest"}:
            raise JavaPluginRegistryError("Java plugin transport must be 'jar' or 'rest'.")
        if document.get("sha256") is not None:
            sha256_value = document.get("sha256")
            if not isinstance(sha256_value, str) or not sha256_value.strip():
                raise JavaPluginRegistryError("Java plugin manifest sha256 must be a non-empty string when provided.")

        manifest = JavaPluginManifest(
            name=self._required_string(document, "name"),
            version=self._required_string(document, "version"),
            author=self._required_string(document, "author"),
            description=self._required_string(document, "description"),
            supported_artifact_types=self._string_list(document, "supported_artifact_types"),
            supported_investigation_stages=self._string_list(document, "supported_investigation_stages"),
            required_java_version=self._required_string(document, "required_java_version"),
            transport=transport,
            manifest_path=manifest_path.resolve(),
            jar_path=self._jar_path(document, manifest_path) if transport == "jar" else None,
            rest_endpoint=self._required_string(document, "rest_endpoint") if transport == "rest" else None,
            sha256=(document.get("sha256") if document.get("sha256") is not None else None),
        )

        self._validate_location(manifest)
        return manifest

    def _jar_path(self, document: dict[str, Any], manifest_path: Path) -> Path:
        """Resolve a manifest-declared JAR path relative to its manifest directory."""
        jar_path = (manifest_path.parent / self._required_string(document, "jar_file")).resolve()
        if jar_path.suffix.lower() != ".jar":
            raise JavaPluginRegistryError("Java plugin jar_file must reference a .jar file.")
        return jar_path

    def _validate_location(self, manifest: JavaPluginManifest) -> None:
        """Ensure manifest and optional JAR are contained in the trusted plugin root."""
        for location in (manifest.manifest_path, manifest.jar_path):
            if location is None:
                continue
            try:
                location.relative_to(self._plugin_root)
            except ValueError as error:
                raise JavaPluginRegistryError("Java plugin assets must remain under the plugin root.") from error
        if manifest.jar_path is not None and not manifest.jar_path.is_file():
            raise JavaPluginRegistryError(f"Java plugin JAR does not exist: {manifest.jar_path}")

    @staticmethod
    def _required_string(document: dict[str, Any], key: str) -> str:
        """Return one required non-empty string from a plugin manifest object."""
        value = document.get(key)
        if not isinstance(value, str) or not value.strip():
            raise JavaPluginRegistryError(f"Java plugin manifest {key!r} must be a non-empty string.")
        return value.strip()

    @staticmethod
    def _string_list(document: dict[str, Any], key: str) -> tuple[str, ...]:
        """Return one required list of non-empty strings from a plugin manifest."""
        value = document.get(key)
        if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
            raise JavaPluginRegistryError(f"Java plugin manifest {key!r} must be a string array.")
        return tuple(item.strip() for item in value)
