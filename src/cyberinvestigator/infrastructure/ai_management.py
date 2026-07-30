"""Persistence hydration for provider-neutral AI runtime configuration."""

from __future__ import annotations

import json

from sqlalchemy import select

from cyberinvestigator.infrastructure.database.models import Setting
from cyberinvestigator.infrastructure.security.credential_vault import CredentialVault, CredentialVaultUnavailable

PROVIDER_CONFIG_KEYS = {
    "nvidia": ("NVIDIA_API_KEY", "NVIDIA_MODEL"),
    "openrouter": ("OPENROUTER_API_KEY", "OPENROUTER_MODEL"),
    "groq": ("GROQ_API_KEY", "GROQ_MODEL"),
    "deepseek": ("DEEPSEEK_API_KEY", "DEEPSEEK_MODEL"),
    "custom": ("CUSTOM_AI_API_KEY", "CUSTOM_AI_MODEL"),
    "openai": ("OPENAI_API_KEY", "OPENAI_MODEL"),
    "gemini": ("GEMINI_API_KEY", "GEMINI_MODEL"),
    "claude": ("ANTHROPIC_API_KEY", "ANTHROPIC_MODEL"),
    "perplexity": ("PERPLEXITY_API_KEY", "PERPLEXITY_MODEL"),
    "ollama": (None, "OLLAMA_MODEL"),
}


def hydrate_ai_config(config: dict, database_session) -> dict:
    """Merge encrypted provider credentials and persisted metadata into runtime config."""
    hydrated = dict(config)
    for provider, (credential_key, model_key) in PROVIDER_CONFIG_KEYS.items():
        metadata = database_session.scalar(
            select(Setting).where(Setting.namespace == "ai.providers", Setting.key == provider)
        )
        if metadata is not None:
            try:
                document = json.loads(metadata.value)
            except (TypeError, json.JSONDecodeError):
                document = {}
            if document.get("model"):
                hydrated[model_key] = str(document["model"])
            if provider == "ollama" and document.get("endpoint"):
                hydrated["OLLAMA_ENDPOINT"] = str(document["endpoint"])
        if credential_key:
            secret = database_session.scalar(
                select(Setting).where(Setting.namespace == "secret.ai", Setting.key == provider)
            )
            if secret is not None:
                try:
                    vault = CredentialVault(str(hydrated.get("AI_CREDENTIAL_ENCRYPTION_KEY") or hydrated["SECRET_KEY"]))
                    hydrated[credential_key] = vault.decrypt(secret.value)
                except (KeyError, CredentialVaultUnavailable):
                    hydrated[credential_key] = None
    return hydrated
