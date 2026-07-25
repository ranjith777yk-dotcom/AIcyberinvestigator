"""Thread-safe dynamic plugin registration without plugin execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock
from types import MappingProxyType
from typing import Mapping, Protocol

from cyberinvestigator.domain.services.artifact_engine import ArtifactType


@dataclass(frozen=True, slots=True, kw_only=True)
class PluginDependency:
    """A declared runtime dependency for a plugin."""

    name: str
    version_specifier: str | None = None
    required: bool = True


@dataclass(frozen=True, slots=True, kw_only=True)
class PluginConfiguration:
    """Immutable plugin configuration schema and declared default values."""

    schema: Mapping[str, object] = field(default_factory=dict)
    defaults: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Defensively copy mappings so registration metadata cannot be mutated."""
        object.__setattr__(self, "schema", MappingProxyType(dict(self.schema)))
        object.__setattr__(self, "defaults", MappingProxyType(dict(self.defaults)))


@dataclass(frozen=True, slots=True, kw_only=True)
class PluginMetadata:
    """Complete, immutable declaration for a dynamically registered plugin."""

    identifier: str
    name: str
    version: str
    description: str
    supported_artifact_types: tuple[ArtifactType, ...] = ()
    capabilities: tuple[str, ...] = ()
    dependencies: tuple[PluginDependency, ...] = ()
    configuration: PluginConfiguration = field(default_factory=PluginConfiguration)
    category: str = "analysis"
    permissions: tuple[str, ...] = ()


class Plugin(Protocol):
    """Minimal plugin contract accepted by the registry.

    The registry reads this declaration only. It does not call plugin execution,
    analysis, initialization, or dependency-resolution methods.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Return immutable metadata describing this plugin."""
        ...


class PluginRegistrationError(ValueError):
    """Raised when a dynamic plugin registration violates registry invariants."""


class PluginRegistry:
    """Instance-scoped, thread-safe registry for dynamically supplied plugins."""

    def __init__(self) -> None:
        """Create an empty registry with no built-in or hardcoded plugins."""
        self._plugins: dict[str, Plugin] = {}
        self._lock = RLock()

    def register(self, plugin: Plugin) -> None:
        """Register a plugin by its unique declared metadata identifier.

        Raises:
            PluginRegistrationError: If the plugin identifier is empty or already
                registered in this registry instance.
        """
        metadata = plugin.metadata
        identifier = metadata.identifier.strip()
        if not identifier:
            raise PluginRegistrationError("Plugin metadata identifier must not be empty.")

        with self._lock:
            if identifier in self._plugins:
                raise PluginRegistrationError(f"Plugin {identifier!r} is already registered.")
            self._plugins[identifier] = plugin

    def unregister(self, identifier: str) -> Plugin:
        """Remove and return a dynamically registered plugin.

        Raises:
            KeyError: If no plugin has the supplied identifier.
        """
        with self._lock:
            return self._plugins.pop(identifier)

    def get(self, identifier: str) -> Plugin:
        """Return a registered plugin without invoking it.

        Raises:
            KeyError: If no plugin has the supplied identifier.
        """
        with self._lock:
            return self._plugins[identifier]

    def metadata(self, identifier: str) -> PluginMetadata:
        """Return the metadata for one registered plugin.

        Raises:
            KeyError: If no plugin has the supplied identifier.
        """
        return self.get(identifier).metadata

    def list_metadata(self) -> tuple[PluginMetadata, ...]:
        """Return metadata for all registered plugins in registration order."""
        with self._lock:
            return tuple(plugin.metadata for plugin in self._plugins.values())

    def contains(self, identifier: str) -> bool:
        """Return whether an identifier is registered in this registry instance."""
        with self._lock:
            return identifier in self._plugins
