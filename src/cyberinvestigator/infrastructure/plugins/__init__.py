"""Plugin registration infrastructure."""

from cyberinvestigator.infrastructure.plugins.loader import (
    LoadedPlugin,
    PluginLoader,
    PluginLoadError,
    PluginManifest,
    PluginStatus,
)
from cyberinvestigator.infrastructure.plugins.registry import (
    Plugin,
    PluginConfiguration,
    PluginDependency,
    PluginMetadata,
    PluginRegistrationError,
    PluginRegistry,
)

__all__ = [
    "Plugin",
    "LoadedPlugin",
    "PluginLoader",
    "PluginLoadError",
    "PluginManifest",
    "PluginStatus",
    "PluginConfiguration",
    "PluginDependency",
    "PluginMetadata",
    "PluginRegistrationError",
    "PluginRegistry",
]
