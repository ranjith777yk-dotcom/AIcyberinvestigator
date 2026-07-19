"""Adapters for dynamically discovered Java investigation plugins."""

from cyberinvestigator.infrastructure.java_plugins.registry import (
    JavaPluginManifest,
    JavaPluginRegistry,
    JavaPluginRegistryError,
)
from cyberinvestigator.infrastructure.java_plugins.runner import (
    JarJavaPluginTransport,
    JavaPluginExecutionResult,
    JavaPluginExecutionStatus,
    JavaPluginRunner,
    JavaPluginRunnerError,
    JavaPluginTransport,
    PluginExecutionResult,
    RestJavaPluginTransport,
)

__all__ = [
    "JarJavaPluginTransport",
    "PluginExecutionResult",
    "JavaPluginExecutionResult",
    "JavaPluginExecutionStatus",
    "JavaPluginManifest",
    "JavaPluginRegistry",
    "JavaPluginRegistryError",
    "JavaPluginRunner",
    "JavaPluginRunnerError",
    "JavaPluginTransport",
    "RestJavaPluginTransport",
]
