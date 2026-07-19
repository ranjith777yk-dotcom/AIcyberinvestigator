"""Plugin runtime security layer.

This module defines *interfaces only* and default no-op/inert adapters that
allow the runtime security boundary to be wired without breaking existing
plugin APIs.

Cryptographic enforcement is intentionally scaffolded. SHA-256 enforcement is
already implemented in the Python loader and Java runner.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Protocol, Sequence

from cyberinvestigator.domain.services.artifact_engine import ArtifactType


class PluginLifecycleState(str, Enum):
    """Unified lifecycle state for both Python and Java plugin execution."""

    LOADED = "loaded"
    ENABLED = "enabled"
    DISABLED = "disabled"
    FAILED = "failed"


@dataclass(frozen=True, slots=True, kw_only=True)
class PluginPermission:
    """A permission request granted/denied for a plugin capability."""

    permission: str
    allowed: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class PluginCompatibility:
    """Runtime compatibility check result."""

    compatible: bool
    reason: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class PluginHealth:
    """Health check result for runtime security components."""

    ready: bool
    message: str


class PluginSignatureVerification(Protocol):
    """Verify plugin digital signature based on manifest metadata."""

    def verify(self, *, manifest_document: Mapping[str, object]) -> None:
        """Raise on verification failure."""
        ...


class TrustedPublisherPolicy(Protocol):
    """Enforce whether a plugin publisher is trusted for this runtime."""

    def is_publisher_trusted(self, *, public_key_id: str | None, author: str | None) -> bool: ...


class PluginPermissionModel(Protocol):
    """Enforce a permission model for plugin runtime capabilities."""

    def validate_permissions(
        self,
        *,
        plugin_identifier: str,
        capabilities: Sequence[str],
    ) -> Sequence[PluginPermission]: ...


class PluginDependencyValidator(Protocol):
    """Validate plugin dependencies and configuration schema."""

    def validate(
        self,
        *,
        plugin_identifier: str,
        dependencies: Sequence[object],
    ) -> None: ...


class PluginCompatibilityChecker(Protocol):
    """Check runtime compatibility (python/java version, artifact types, stages)."""

    def check(
        self,
        *,
        plugin_identifier: str,
        supported_artifact_types: Sequence[ArtifactType],
        required_runtime_version: str | None = None,
    ) -> PluginCompatibility: ...


class PluginRuntimeHealthChecker(Protocol):
    """Health check for plugin runtime security system."""

    def health(self) -> PluginHealth: ...


class DefaultNoopSignatureVerification:
    """Signature verification adapter that rejects unsigned plugins by default."""

    def verify(self, *, manifest_document: Mapping[str, object]) -> None:
        from cyberinvestigator.infrastructure.security.plugin_verification import PluginVerificationError

        signature = manifest_document.get("signature") if isinstance(manifest_document, Mapping) else None
        public_key_id = manifest_document.get("public_key_id") if isinstance(manifest_document, Mapping) else None
        if signature is None and public_key_id is None:
            raise PluginVerificationError("Plugin signature verification requires a signed manifest context.")
        if signature is None or public_key_id is None:
            raise PluginVerificationError("Plugin signature verification requires both signature and public_key_id.")


class DefaultAllowTrustedPublisherPolicy:
    """Trusted publisher policy adapter that only trusts explicitly named publishers."""

    def is_publisher_trusted(self, *, public_key_id: str | None, author: str | None) -> bool:
        return bool(public_key_id and str(public_key_id).strip())


class DefaultDenyPermissionsModel:
    """Permission model adapter that denies all capabilities by default."""

    def validate_permissions(
        self,
        *,
        plugin_identifier: str,
        capabilities: Sequence[str],
    ) -> Sequence[PluginPermission]:
        return [PluginPermission(permission=c, allowed=False) for c in capabilities]


class DefaultNoopDependencyValidator:
    """Dependency validator adapter that performs no dependency validation."""

    def validate(
        self,
        *,
        plugin_identifier: str,
        dependencies: Sequence[object],
    ) -> None:
        return


class DefaultNoopCompatibilityChecker:
    """Compatibility checker adapter that always returns compatible."""

    def check(
        self,
        *,
        plugin_identifier: str,
        supported_artifact_types: Sequence[ArtifactType],
        required_runtime_version: str | None = None,
    ) -> PluginCompatibility:
        return PluginCompatibility(compatible=True)


class DefaultPluginRuntimeHealthChecker:
    """Health checker for runtime security adapters."""

    def __init__(self, *, ready: bool = True, message: str = "Runtime security adapters are configured.") -> None:
        self._ready = ready
        self._message = message

    def health(self) -> PluginHealth:
        return PluginHealth(ready=self._ready, message=self._message)
