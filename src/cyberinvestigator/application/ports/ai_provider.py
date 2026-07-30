"""Strategy interfaces for interchangeable AI providers.

This module contains provider-neutral contracts only.  It does not import SDKs,
access credentials, make network requests, or implement model invocation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterator, Mapping, Protocol


class AIProviderName(str, Enum):
    """Supported provider families available to the strategy boundary."""

    OPENAI = "openai"
    NVIDIA = "nvidia"
    OPENROUTER = "openrouter"
    GROQ = "groq"
    DEEPSEEK = "deepseek"
    CUSTOM = "custom"
    GEMINI = "gemini"
    PERPLEXITY = "perplexity"
    CLAUDE = "claude"
    OLLAMA = "ollama"
    LM_STUDIO = "lm_studio"


@dataclass(frozen=True, slots=True, kw_only=True)
class AIMessage:
    """A provider-neutral message supplied to an AI strategy."""

    role: str
    content: str


@dataclass(frozen=True, slots=True, kw_only=True)
class AIRequest:
    """A provider-neutral request contract for an AI strategy."""

    model: str
    messages: tuple[AIMessage, ...]
    temperature: float | None = None
    max_output_tokens: int | None = None
    stream: bool = False
    metadata: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True, kw_only=True)
class AIUsage:
    """Provider-reported token usage returned by an AI strategy."""

    input_tokens: int | None = None
    output_tokens: int | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class AIResponse:
    """A provider-neutral response contract returned by an AI strategy."""

    content: str
    model: str
    provider: AIProviderName
    usage: AIUsage | None = None
    response_id: str | None = None


class AIProviderStrategy(ABC):
    """Abstract strategy for one AI provider family.

    Concrete implementations own provider-specific SDKs, authentication, error
    translation, and invocation behavior; none are defined in this module.
    """

    @property
    @abstractmethod
    def provider_name(self) -> AIProviderName:
        """Return the provider family served by this strategy."""
        ...

    @abstractmethod
    def generate(self, request: AIRequest) -> AIResponse:
        """Generate a provider-neutral response for one normalized request."""
        ...

    def stream(self, request: AIRequest) -> Iterator[str]:
        """Yield a provider-neutral streamed response.

        Providers that do not implement native streaming can safely fall back to
        a single generated chunk.
        """
        yield self.generate(request).content


class BaseAIProvider(AIProviderStrategy, ABC):
    """Provider-agnostic contract.

    This is an alias-style base interface so the application can depend on a
    stable name while still using the Strategy pattern.
    """


class OpenAIProvider(BaseAIProvider, ABC):
    """Abstract strategy contract for an OpenAI provider implementation."""


class NVIDIAProvider(BaseAIProvider, ABC):
    """Abstract strategy contract for NVIDIA's OpenAI-compatible API."""


class OpenAICompatibleProvider(BaseAIProvider, ABC):
    """Contract for a provider offering the OpenAI chat-completions protocol."""


class GeminiProvider(BaseAIProvider, ABC):
    """Abstract strategy contract for a Gemini provider implementation."""


class PerplexityProvider(BaseAIProvider, ABC):
    """Abstract strategy contract for a Perplexity provider implementation."""


class ClaudeProvider(BaseAIProvider, ABC):
    """Abstract strategy contract for a Claude provider implementation."""


class OllamaProvider(BaseAIProvider, ABC):
    """Abstract strategy contract for an Ollama provider implementation."""


# Backwards-compatible strategy interface names (used by existing code/tests)
class OpenAIProviderStrategy(OpenAIProvider, ABC):
    """Abstract strategy contract for an OpenAI provider implementation."""


class NVIDIAProviderStrategy(NVIDIAProvider, ABC):
    """Abstract strategy contract for NVIDIA's OpenAI-compatible API."""


class OpenAICompatibleProviderStrategy(OpenAICompatibleProvider, ABC):
    """Contract for OpenAI-compatible third-party provider implementations."""


class GeminiProviderStrategy(GeminiProvider, ABC):
    """Abstract strategy contract for a Gemini provider implementation."""


class PerplexityProviderStrategy(PerplexityProvider, ABC):
    """Abstract strategy contract for a Perplexity provider implementation."""


class ClaudeProviderStrategy(ClaudeProvider, ABC):
    """Abstract strategy contract for a Claude provider implementation."""


class OllamaProviderStrategy(OllamaProvider, ABC):
    """Abstract strategy contract for an Ollama provider implementation."""


class LMStudioProviderStrategy(AIProviderStrategy, ABC):
    """Abstract strategy contract for an LM Studio provider implementation."""


class AIProviderSelector(Protocol):
    """Selection boundary that resolves a strategy for a requested provider."""

    def select(self, provider_name: AIProviderName) -> AIProviderStrategy:
        """Return the strategy registered for a provider family."""
        ...
