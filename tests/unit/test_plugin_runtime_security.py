"""Unit tests for plugin runtime security layer.

These tests validate that the security boundary is importable and that the
default adapters behave deterministically.
"""

from __future__ import annotations

import pytest

from cyberinvestigator.domain.services import ArtifactType
from cyberinvestigator.infrastructure.security.plugin_runtime_security import (
    DefaultAllowTrustedPublisherPolicy,
    DefaultDenyPermissionsModel,
    DefaultNoopCompatibilityChecker,
    DefaultNoopDependencyValidator,
    DefaultNoopSignatureVerification,
    DefaultPluginRuntimeHealthChecker,
)
from cyberinvestigator.infrastructure.security.plugin_verification import PluginVerificationError


def test_default_signature_verification_requires_explicit_signature_context() -> None:
    verifier = DefaultNoopSignatureVerification()
    with pytest.raises(PluginVerificationError, match="signature"):
        verifier.verify(manifest_document={"signature": "abc"})


def test_default_trusted_publisher_policy_requires_explicit_trust() -> None:
    policy = DefaultAllowTrustedPublisherPolicy()
    assert policy.is_publisher_trusted(public_key_id=None, author="someone") is False
    assert policy.is_publisher_trusted(public_key_id="trusted-publisher", author="someone") is True


def test_default_permissions_model_denies_capabilities_by_default() -> None:
    model = DefaultDenyPermissionsModel()
    perms = model.validate_permissions(
        plugin_identifier="p",
        capabilities=["read:file", "write:file"],
    )
    assert [p.permission for p in perms] == ["read:file", "write:file"]
    assert not any(p.allowed for p in perms)


def test_default_compatibility_checker_always_compatible() -> None:
    checker = DefaultNoopCompatibilityChecker()
    compat = checker.check(
        plugin_identifier="p",
        supported_artifact_types=[ArtifactType.PDF],
        required_runtime_version="1",
    )
    assert compat.compatible is True


def test_default_dependency_validator_noop() -> None:
    validator = DefaultNoopDependencyValidator()
    validator.validate(plugin_identifier="p", dependencies=[object()])


def test_health_checker_reports_ready() -> None:
    health = DefaultPluginRuntimeHealthChecker().health()
    assert health.ready is True
    assert "Runtime security" in health.message
