"""Unit tests for provider strategy contracts."""

import inspect

from cyberinvestigator.application.ports import (
    AIProviderName,
    AIProviderStrategy,
    ClaudeProviderStrategy,
    GeminiProviderStrategy,
    LMStudioProviderStrategy,
    OllamaProviderStrategy,
    OpenAIProviderStrategy,
    PerplexityProviderStrategy,
)


def test_all_supported_provider_families_are_declared() -> None:
    """The strategy boundary declares every requested provider family."""
    assert {provider.value for provider in AIProviderName} == {
        "openai",
        "gemini",
        "perplexity",
        "claude",
        "ollama",
        "lm_studio",
    }


def test_provider_strategies_remain_abstract_interfaces() -> None:
    """Provider-specific contracts contain no concrete provider implementation."""
    strategies = (
        AIProviderStrategy,
        OpenAIProviderStrategy,
        GeminiProviderStrategy,
        PerplexityProviderStrategy,
        ClaudeProviderStrategy,
        OllamaProviderStrategy,
        LMStudioProviderStrategy,
    )

    assert all(inspect.isabstract(strategy) for strategy in strategies)
