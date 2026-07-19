"""Manifest-based lifecycle management for trusted Python plugins.

Python cannot safely sandbox arbitrary imported code.  This loader therefore
only discovers plugins from an explicitly supplied, trusted directory and
validates their manifests and metadata before activating them in the registry.
"""

from __future__ import annotations

import importlib.util
import sys
import tomllib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from threading import RLock
from types import ModuleType
from typing import Any

from cyberinvestigator.infrastructure.plugins.registry import (
    Plugin,
    PluginMetadata,
    PluginRegistrationError,
    PluginRegistry,
)
from cyberinvestigator.infrastructure.security.plugin_verification import (
    PluginVerificationError,
    sha256_file,
)


class PluginLoadError(RuntimeError):
    """Raised when plugin discovery, validation, or lifecycle operations fail."""


class PluginStatus(str, Enum):
    """Lifecycle states maintained by a loader instance."""

    LOADED = "loaded"
    ENABLED = "enabled"
    DISABLED = "disabled"


@dataclass(frozen=True, slots=True, kw_only=True)
class PluginManifest:
    """Validated plugin location and identity declared in ``plugin.toml``."""

    identifier: str
    name: str
    version: str
    module_file: Path
    object_name: str
    enabled: bool
    sha256: str | None = None


@dataclass(slots=True)
class LoadedPlugin:
    """Runtime state for one loaded plugin in a specific loader instance."""

    manifest: PluginManifest
    plugin: Plugin
    module_name: str
    status: PluginStatus


class PluginLoader:
    """Discover, validate, load, activate, deactivate, and unload trusted plugins."""

    def __init__(self, plugin_root: Path, registry: PluginRegistry) -> None:
        """Create a loader constrained to one trusted plugin root directory."""
        self._plugin_root = plugin_root.resolve()
        self._registry = registry
        self._loaded: dict[str, LoadedPlugin] = {}
        self._lock = RLock()

    def discover(self) -> tuple[PluginManifest, ...]:
        """Discover and validate manifests in direct child directories of the root."""
        if not self._plugin_root.exists():
            return ()
        if not self._plugin_root.is_dir():
            raise PluginLoadError("Plugin root must be a directory.")

        manifests = []
        for manifest_path in sorted(self._plugin_root.glob("*/plugin.toml")):
            manifests.append(self._read_manifest(manifest_path))
        return tuple(manifests)

    def load_discovered(self) -> tuple[LoadedPlugin, ...]:
        """Load discovered plugins and activate only manifests marked enabled."""
        loaded = []
        for manifest in self.discover():
            record = self.load(manifest)
            if manifest.enabled:
                self.enable(manifest.identifier)
            loaded.append(record)
        return tuple(loaded)

    def load(self, manifest: PluginManifest) -> LoadedPlugin:
        """Load and validate a trusted plugin without automatically activating it."""
        self.validate_manifest(manifest)
        with self._lock:
            if manifest.identifier in self._loaded:
                raise PluginLoadError(f"Plugin {manifest.identifier!r} is already loaded.")

            module_name = self._module_name(manifest.identifier)
            if manifest.sha256:
                try:
                    computed = sha256_file(manifest.module_file)
                except PluginVerificationError as error:
                    raise PluginLoadError(str(error)) from error
                if computed.lower() != manifest.sha256.strip().lower():
                    raise PluginLoadError(f"Plugin module SHA-256 mismatch for {manifest.identifier!r}.")

            module = self._import_module(manifest.module_file, module_name)
            try:
                plugin = self._plugin_from_module(module, manifest.object_name)
                self.validate_plugin(plugin, manifest)

            except Exception:
                sys.modules.pop(module_name, None)
                raise

            record = LoadedPlugin(
                manifest=manifest,
                plugin=plugin,
                module_name=module_name,
                status=PluginStatus.LOADED,
            )
            self._loaded[manifest.identifier] = record
            return record

    def unload(self, identifier: str) -> None:
        """Deactivate and remove a loaded plugin from this loader instance."""
        with self._lock:
            record = self._loaded.pop(identifier)
            if record.status is PluginStatus.ENABLED:
                self._registry.unregister(identifier)
            sys.modules.pop(record.module_name, None)

    def enable(self, identifier: str) -> None:
        """Activate a loaded plugin by registering it with the plugin registry."""
        with self._lock:
            record = self._get_loaded(identifier)
            if record.status is PluginStatus.ENABLED:
                return
            try:
                self._registry.register(record.plugin)
            except PluginRegistrationError as error:
                raise PluginLoadError(str(error)) from error
            record.status = PluginStatus.ENABLED

    def disable(self, identifier: str) -> None:
        """Deactivate a loaded plugin while retaining its validated module in memory."""
        with self._lock:
            record = self._get_loaded(identifier)
            if record.status is not PluginStatus.ENABLED:
                record.status = PluginStatus.DISABLED
                return
            self._registry.unregister(identifier)
            record.status = PluginStatus.DISABLED

    def reload(self, identifier: str) -> LoadedPlugin:
        """Unload and re-import a plugin, restoring its prior activation state."""
        with self._lock:
            record = self._get_loaded(identifier)
            manifest = record.manifest
            was_enabled = record.status is PluginStatus.ENABLED
            self.unload(identifier)
            reloaded = self.load(manifest)
            if was_enabled:
                self.enable(identifier)
            return reloaded

    def status(self, identifier: str) -> PluginStatus:
        """Return the lifecycle status for a plugin loaded by this instance."""
        with self._lock:
            return self._get_loaded(identifier).status

    def validate_manifest(self, manifest: PluginManifest) -> None:
        """Validate manifest identity and ensure the module remains under the root."""
        if not manifest.identifier.strip() or not manifest.name.strip() or not manifest.version.strip():
            raise PluginLoadError("Plugin identifier, name, and version must not be empty.")
        if manifest.sha256 is not None:
            if not isinstance(manifest.sha256, str) or not manifest.sha256.strip():
                raise PluginLoadError("Plugin manifest sha256 must be a non-empty string when provided.")

        if not manifest.object_name.isidentifier():
            raise PluginLoadError("Plugin object name must be a valid Python identifier.")
        try:
            manifest.module_file.resolve().relative_to(self._plugin_root)
        except ValueError as error:
            raise PluginLoadError("Plugin module must be located under the trusted plugin root.") from error
        if manifest.module_file.suffix != ".py" or not manifest.module_file.is_file():
            raise PluginLoadError("Plugin module_file must reference an existing Python file.")

    @staticmethod
    def validate_plugin(plugin: Plugin, manifest: PluginManifest) -> None:
        """Validate the loaded plugin's metadata against its trusted manifest."""
        metadata = plugin.metadata
        if not isinstance(metadata, PluginMetadata):
            raise PluginLoadError("Plugin metadata must be a PluginMetadata instance.")
        if (metadata.identifier, metadata.name, metadata.version) != (
            manifest.identifier,
            manifest.name,
            manifest.version,
        ):
            raise PluginLoadError("Plugin metadata does not match its manifest identity.")

    def _read_manifest(self, manifest_path: Path) -> PluginManifest:
        """Parse one TOML manifest without importing its plugin module."""
        try:
            with manifest_path.open("rb") as manifest_file:
                document: dict[str, Any] = tomllib.load(manifest_file)
            plugin = document["plugin"]
            if not isinstance(plugin, dict):
                raise TypeError("[plugin] must be a TOML table")
            manifest = PluginManifest(
                identifier=self._required_string(plugin, "identifier"),
                name=self._required_string(plugin, "name"),
                version=self._required_string(plugin, "version"),
                module_file=(manifest_path.parent / self._required_string(plugin, "module")).resolve(),
                object_name=self._required_string(plugin, "object"),
                enabled=plugin.get("enabled", True),
                sha256=(plugin.get("sha256") if plugin.get("sha256") is not None else None),
            )

        except (KeyError, OSError, TypeError, tomllib.TOMLDecodeError) as error:
            raise PluginLoadError(f"Invalid plugin manifest: {manifest_path}") from error

        if not isinstance(manifest.enabled, bool):
            raise PluginLoadError("Plugin manifest enabled must be a boolean.")
        self.validate_manifest(manifest)
        return manifest

    @staticmethod
    def _required_string(document: dict[str, Any], key: str) -> str:
        """Return a required, non-empty string from a parsed manifest table."""
        value = document[key]
        if not isinstance(value, str) or not value.strip():
            raise TypeError(f"Plugin manifest {key!r} must be a non-empty string.")
        return value.strip()

    @staticmethod
    def _import_module(module_path: Path, module_name: str) -> ModuleType:
        """Import a trusted module file under a loader-owned module name."""
        specification = importlib.util.spec_from_file_location(module_name, module_path)
        if specification is None or specification.loader is None:
            raise PluginLoadError(f"Unable to create an import specification for {module_path}.")
        module = importlib.util.module_from_spec(specification)
        sys.modules[module_name] = module
        try:
            specification.loader.exec_module(module)
        except Exception as error:
            sys.modules.pop(module_name, None)
            raise PluginLoadError(f"Unable to import plugin module {module_path.name!r}.") from error
        return module

    @staticmethod
    def _plugin_from_module(module: ModuleType, object_name: str) -> Plugin:
        """Obtain a declared plugin instance without invoking plugin operations."""
        try:
            candidate = getattr(module, object_name)
        except AttributeError as error:
            raise PluginLoadError(f"Plugin module has no {object_name!r} object.") from error
        if not hasattr(candidate, "metadata"):
            raise PluginLoadError("Plugin object must expose metadata.")
        return candidate

    @staticmethod
    def _module_name(identifier: str) -> str:
        """Create an isolated, valid module name for a plugin identifier."""
        return "cyberinvestigator_plugin_" + "".join(
            character if character.isalnum() else "_" for character in identifier
        )

    def _get_loaded(self, identifier: str) -> LoadedPlugin:
        """Return a loaded record or raise a domain-specific lifecycle error."""
        try:
            return self._loaded[identifier]
        except KeyError as error:
            raise PluginLoadError(f"Plugin {identifier!r} is not loaded.") from error
