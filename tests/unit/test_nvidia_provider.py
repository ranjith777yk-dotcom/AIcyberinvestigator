"""Tests for the NVIDIA OpenAI-compatible provider adapter."""

from types import SimpleNamespace

from cyberinvestigator.application.ports import AIMessage, AIProviderName, AIRequest
from cyberinvestigator.infrastructure.ai import NVIDIAOpenAIProvider, build_ai_registry


class _Completions:
    def __init__(self, response) -> None:
        self.response = response
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


def _request(*, stream: bool = False) -> AIRequest:
    return AIRequest(
        model="meta/llama-3.3-70b-instruct",
        messages=(AIMessage(role="user", content="Summarize this evidence."),),
        temperature=0.2,
        max_output_tokens=64,
        stream=stream,
    )


def test_nvidia_provider_uses_chat_completions_and_reuses_its_client() -> None:
    response = SimpleNamespace(
        id="response-1",
        model="meta/llama-3.3-70b-instruct",
        choices=[SimpleNamespace(message=SimpleNamespace(content="Grounded summary."))],
        usage=SimpleNamespace(prompt_tokens=11, completion_tokens=3),
    )
    completions = _Completions(response)
    provider = NVIDIAOpenAIProvider(api_key="test-key", model="test-model", base_url="https://example.test/v1")
    provider._client = SimpleNamespace(chat=SimpleNamespace(completions=completions))

    result = provider.generate(_request())

    assert result.content == "Grounded summary."
    assert result.provider is AIProviderName.NVIDIA
    assert result.usage and result.usage.input_tokens == 11
    assert completions.calls[0]["temperature"] == 0.2
    assert completions.calls[0]["max_tokens"] == 64


def test_nvidia_provider_streams_text_chunks() -> None:
    chunks = iter(
        [
            SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content="Threat "))]),
            SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content="contained."))]),
        ]
    )
    completions = _Completions(chunks)
    provider = NVIDIAOpenAIProvider(api_key="test-key", model="test-model", base_url="https://example.test/v1")
    provider._client = SimpleNamespace(chat=SimpleNamespace(completions=completions))

    assert "".join(provider.stream(_request(stream=True))) == "Threat contained."
    assert completions.calls[0]["stream"] is True


def test_nvidia_is_the_default_registered_provider() -> None:
    registry = build_ai_registry({"NVIDIA_API_KEY": "test-key"})

    assert registry.select("nvidia").provider_name is AIProviderName.NVIDIA
