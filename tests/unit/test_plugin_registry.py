"""Unit tests for dynamic plugin registration."""

from types import SimpleNamespace

import pytest

from cyberinvestigator.domain.services import ArtifactType
from cyberinvestigator.infrastructure.plugins import (
    PluginConfiguration,
    PluginMetadata,
    PluginRegistrationError,
    PluginRegistry,
)


def test_register_and_unregister_dynamic_plugin() -> None:
    """A registry stores only dynamically supplied plugin instances."""
    registry = PluginRegistry()
    plugin = SimpleNamespace(
        metadata=PluginMetadata(
            identifier="pdf-review",
            name="PDF Review",
            version="1.0.0",
            description="Test plugin",
            supported_artifact_types=(ArtifactType.PDF,),
            capabilities=("review",),
            configuration=PluginConfiguration(defaults={"enabled": True}),
        )
    )

    registry.register(plugin)

    assert registry.contains("pdf-review")
    assert registry.list_metadata() == (plugin.metadata,)
    assert registry.unregister("pdf-review") is plugin


def test_duplicate_plugin_identifier_is_rejected() -> None:
    """Plugin identifiers are unique per registry instance."""
    registry = PluginRegistry()
    plugin = SimpleNamespace(
        metadata=PluginMetadata(identifier="unique", name="Unique", version="1.0.0", description="Test")
    )
    registry.register(plugin)

    with pytest.raises(PluginRegistrationError, match="already registered"):
        registry.register(plugin)
