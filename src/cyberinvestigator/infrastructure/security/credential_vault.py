"""Application-level encryption for persisted provider credentials."""

from __future__ import annotations

import base64
import hashlib


class CredentialVaultUnavailable(RuntimeError):
    """Raised when credential encryption cannot be initialized safely."""


class CredentialVault:
    """Encrypt secrets at rest without exposing plaintext through settings APIs."""

    def __init__(self, encryption_secret: str) -> None:
        if len(str(encryption_secret)) < 32:
            raise CredentialVaultUnavailable("Credential encryption requires a secret of at least 32 characters.")
        try:
            from cryptography.fernet import Fernet
        except ImportError as error:  # pragma: no cover - dependency is mandatory in packaged deployments.
            raise CredentialVaultUnavailable("The credential encryption dependency is unavailable.") from error
        key = base64.urlsafe_b64encode(hashlib.sha256(str(encryption_secret).encode("utf-8")).digest())
        self._fernet = Fernet(key)

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, ciphertext: str) -> str:
        try:
            return self._fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")
        except Exception as error:
            raise CredentialVaultUnavailable("Stored credential could not be decrypted.") from error
