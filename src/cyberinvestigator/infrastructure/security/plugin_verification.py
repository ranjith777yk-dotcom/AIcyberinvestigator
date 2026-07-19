"""Plugin asset verification utilities.

This module provides cryptographic verification helpers used by both Python and
Java plugin execution boundaries.

Current scope:
- SHA-256 hash verification for plugin assets referenced from manifests.
- Signature verification support is intentionally scaffolded for later work
  (to avoid changing existing plugin APIs).

All functions are dependency-injected friendly and include defensive input
validation.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

logger = logging.getLogger(__name__)


class PluginVerificationError(RuntimeError):
    """Raised when plugin asset verification fails."""


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Structured result for one verification attempt."""

    asset_path: str
    expected_sha256: str | None
    computed_sha256: str | None
    reason: str


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    """Compute SHA-256 hash of a file.

    Args:
        path: File path to hash.
        chunk_size: Read chunk size in bytes.

    Returns:
        Hex-encoded SHA-256 digest.

    Raises:
        PluginVerificationError: If the path is not a readable file.
    """
    resolved = path.resolve()
    if not resolved.is_file():
        raise PluginVerificationError(f"Plugin asset must be an existing file: {resolved}")

    digest = hashlib.sha256()
    try:
        with resolved.open("rb") as stream:
            while True:
                chunk = stream.read(chunk_size)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as error:
        raise PluginVerificationError(f"Unable to read plugin asset for hashing: {resolved}") from error

    return digest.hexdigest()


def verify_sha256(path: Path, expected_sha256: str, *, asset_label: str) -> VerificationResult:
    """Verify a file against an expected SHA-256.

    Args:
        path: Asset file path.
        expected_sha256: Expected hex digest (case-insensitive).
        asset_label: Human readable label used in errors/logging.

    Returns:
        VerificationResult with computed/expected digests.

    Raises:
        PluginVerificationError: If computed digest does not match expected.
    """
    expected = expected_sha256.strip().lower()
    computed = sha256_file(path)
    if computed.lower() != expected:
        reason = f"{asset_label} SHA-256 mismatch (expected {expected}, computed {computed})."
        logger.warning("Plugin verification failed: %s", reason)
        raise PluginVerificationError(reason)

    reason = f"{asset_label} SHA-256 verified."

    logger.info("Plugin verification succeeded: %s", reason)
    return VerificationResult(
        asset_path=str(path),
        expected_sha256=expected,
        computed_sha256=computed,
        reason=reason,
    )


def verify_signature_scaffold(
    *,
    manifest_document: Mapping[str, Any],
    signature: str | None,
    public_key_id: str | None,
    trusted_publishers: set[str],
) -> None:
    """Enforce signature context and publisher trust for signed plugin manifests."""
    if signature is None and public_key_id is None:
        raise PluginVerificationError("Plugin signature verification requires a signed manifest context.")

    if signature is None or public_key_id is None:
        raise PluginVerificationError("Plugin signature verification requires both signature and public_key_id.")

    if public_key_id not in trusted_publishers:
        raise PluginVerificationError(f"Untrusted public_key_id: {public_key_id}.")

    if not isinstance(signature, str) or not signature.strip():
        raise PluginVerificationError("Plugin signature must be a non-empty string.")

    logger.info(
        "Signature verification scaffold accepted manifest for public_key_id=%s.",
        public_key_id,
    )
