"""Application-facing AI facade over provider selection and fallback."""

from __future__ import annotations

from typing import Iterator

from cyberinvestigator.application.ports.ai_provider import AIProviderName, AIRequest, AIResponse
from cyberinvestigator.infrastructure.ai import AIProviderManager, ProviderStatus


class AIFeature:
    """Expose provider-neutral AI operations to feature modules."""

    def __init__(self, providers: AIProviderManager) -> None:
        self._providers = providers

    def generate(self, request: AIRequest, provider: AIProviderName | str) -> AIResponse:
        return self._providers.select(provider).generate(request)

    def stream(self, request: AIRequest, provider: AIProviderName | str) -> Iterator[str]:
        return self._providers.select(provider).stream(request)

    def status(self, provider: AIProviderName | str) -> ProviderStatus:
        key = provider.value if isinstance(provider, AIProviderName) else str(provider)
        return self._providers.status(key)

    @property
    def providers(self) -> AIProviderManager:
        """Return the legacy manager during incremental endpoint migration."""
        return self._providers
