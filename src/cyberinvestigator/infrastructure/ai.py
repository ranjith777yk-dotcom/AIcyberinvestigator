"""Provider-based AI adapters with Ollama-first local defaults."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Iterator
from urllib.error import HTTPError, URLError
from urllib.request import Request as UrlRequest
from urllib.request import urlopen

from cyberinvestigator.application.ports.ai_provider import (
    AIMessage,
    AIProviderName,
    AIProviderStrategy,
    AIRequest,
    AIResponse,
    AIUsage,
    GeminiProviderStrategy,
    OllamaProviderStrategy,
    OpenAIProviderStrategy,
    PerplexityProviderStrategy,
)


class AIProviderUnavailable(RuntimeError):
    """Raised when a provider cannot satisfy a request in the current runtime."""


@dataclass(frozen=True, slots=True)
class ProviderStatus:
    """Configuration and health view for one provider."""

    provider: str
    available: bool
    configured: bool
    model: str
    message: str
    endpoint: str | None = None
    installed_models: tuple[str, ...] = ()
    health_source: str = "configuration"
    checked_at: float | None = None


logger = logging.getLogger(__name__)


class OllamaHTTPProvider(OllamaProviderStrategy):
    """Ollama provider implemented against the local HTTP API."""

    def __init__(self, *, endpoint: str, model: str, timeout: int = 60, keep_alive: str = "10m") -> None:
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.keep_alive = keep_alive

    @property
    def provider_name(self) -> AIProviderName:
        return AIProviderName.OLLAMA

    @property
    def status(self) -> ProviderStatus:
        models, error = self._list_models()
        available = error is None
        installed = tuple(models)
        configured = True
        if available and self.model not in installed:
            message = f"Ollama is running, but model '{self.model}' is not installed."
        elif available:
            message = "Ollama is running and ready."
        else:
            message = "Ollama is not reachable at the configured local endpoint."
        return ProviderStatus(
            provider=self.provider_name.value,
            available=available and (not installed or self.model in installed),
            configured=configured,
            model=self.model,
            message=message,
            endpoint=self.endpoint,
            installed_models=installed,
            health_source="live_endpoint",
            checked_at=time.time(),
        )

    def generate(self, request: AIRequest) -> AIResponse:
        started_at = time.perf_counter()
        model = request.model or self.model
        payload = self._payload(request, model=model, stream=False)
        data = self._post_json("/api/chat", payload)
        message = data.get("message") if isinstance(data, dict) else {}
        content = str((message or {}).get("content") or "").strip()
        if not content:
            raise AIProviderUnavailable("Ollama returned an empty response.")
        usage = AIUsage(
            input_tokens=data.get("prompt_eval_count") if isinstance(data, dict) else None,
            output_tokens=data.get("eval_count") if isinstance(data, dict) else None,
        )
        latency_ms = round((time.perf_counter() - started_at) * 1000, 2)
        logger.debug("Ollama completion model=%s latency_ms=%s", model, latency_ms)
        return AIResponse(content=content, model=model, provider=self.provider_name, usage=usage)

    def stream(self, request: AIRequest) -> Iterator[str]:
        model = request.model or self.model
        payload = self._payload(request, model=model, stream=True)
        body = json.dumps(payload).encode("utf-8")
        http_request = UrlRequest(
            f"{self.endpoint}/api/chat",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(http_request, timeout=self.timeout) as response:  # noqa: S310 - user-configured local AI endpoint.
                for raw_line in response:
                    if not raw_line.strip():
                        continue
                    data = json.loads(raw_line.decode("utf-8"))
                    message = data.get("message") or {}
                    chunk = str(message.get("content") or "")
                    if chunk:
                        yield chunk
                    if data.get("done"):
                        break
        except (OSError, HTTPError, URLError, json.JSONDecodeError) as error:
            raise AIProviderUnavailable(str(error)) from error

    def _payload(self, request: AIRequest, *, model: str, stream: bool) -> dict[str, object]:
        options: dict[str, object] = {}
        if request.temperature is not None:
            options["temperature"] = request.temperature
        if request.max_output_tokens is not None:
            options["num_predict"] = request.max_output_tokens
        return {
            "model": model,
            "messages": [{"role": item.role, "content": item.content} for item in request.messages],
            "stream": stream,
            "keep_alive": self.keep_alive,
            "options": options,
        }

    def _list_models(self) -> tuple[list[str], str | None]:
        try:
            data = self._get_json("/api/tags", timeout=3)
            models = data.get("models", []) if isinstance(data, dict) else []
            return [str(item.get("name")) for item in models if isinstance(item, dict) and item.get("name")], None
        except AIProviderUnavailable as error:
            return [], str(error)

    def _get_json(self, path: str, *, timeout: int | None = None) -> dict[str, object]:
        try:
            with urlopen(f"{self.endpoint}{path}", timeout=timeout or self.timeout) as response:  # noqa: S310
                return json.loads(response.read().decode("utf-8"))
        except (OSError, HTTPError, URLError, json.JSONDecodeError) as error:
            raise AIProviderUnavailable(str(error)) from error

    def _post_json(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        body = json.dumps(payload).encode("utf-8")
        request = UrlRequest(
            f"{self.endpoint}{path}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                return json.loads(response.read().decode("utf-8"))
        except (OSError, HTTPError, URLError, json.JSONDecodeError) as error:
            raise AIProviderUnavailable(str(error)) from error


class OpenAISDKProvider(OpenAIProviderStrategy):
    """OpenAI provider implemented with the official Python SDK when installed."""

    def __init__(self, *, api_key: str | None, model: str, base_url: str | None = None, timeout: int = 60) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = (base_url or "https://api.openai.com/v1").rstrip("/")
        self.timeout = timeout
        self._client = None

    @property
    def provider_name(self) -> AIProviderName:
        return AIProviderName.OPENAI

    @property
    def status(self) -> ProviderStatus:
        configured = bool(self.api_key)
        return ProviderStatus(
            provider=self.provider_name.value,
            available=configured,
            configured=configured,
            model=self.model,
            message=(
                "OpenAI adapter is configured; use connection testing to verify live availability."
                if configured
                else "OpenAI API key is not configured."
            ),
            health_source="configuration",
        )

    def test_connection(self) -> ProviderStatus:
        if not self.api_key:
            return self.status
        try:
            self._openai_client().models.list()
        except Exception:
            return ProviderStatus(
                provider=self.provider_name.value,
                available=False,
                configured=True,
                model=self.model,
                message="OpenAI connection test failed; provider details were suppressed.",
                health_source="live_endpoint",
                checked_at=time.time(),
            )
        return ProviderStatus(
            provider=self.provider_name.value,
            available=True,
            configured=True,
            model=self.model,
            message="OpenAI connection test succeeded.",
            health_source="live_endpoint",
            checked_at=time.time(),
        )

    def generate(self, request: AIRequest) -> AIResponse:
        if not self.api_key:
            raise AIProviderUnavailable("OpenAI API key is not configured.")
        started_at = time.perf_counter()
        try:
            client = self._openai_client()
            payload = {
                "model": request.model or self.model,
                "input": [{"role": item.role, "content": item.content} for item in request.messages],
                "temperature": request.temperature if request.temperature is not None else 0.2,
            }
            if request.max_output_tokens is not None:
                payload["max_output_tokens"] = request.max_output_tokens
            response = client.responses.create(**payload)
            content = getattr(response, "output_text", "") or ""
            raw_usage = getattr(response, "usage", None)
        except Exception as error:
            raise AIProviderUnavailable(str(error)) from error
        if not content:
            raise AIProviderUnavailable("OpenAI returned an empty response.")
        usage = AIUsage(
            input_tokens=getattr(raw_usage, "input_tokens", None),
            output_tokens=getattr(raw_usage, "output_tokens", None),
        )
        latency_ms = round((time.perf_counter() - started_at) * 1000, 2)
        logger.debug("OpenAI completion model=%s latency_ms=%s", request.model or self.model, latency_ms)
        return AIResponse(
            content=content.strip(),
            model=getattr(response, "model", None) or request.model or self.model,
            provider=self.provider_name,
            usage=usage,
            response_id=getattr(response, "id", None),
        )

    def _openai_client(self):
        if self._client is None:
            try:
                from openai import OpenAI
            except ImportError as error:
                raise AIProviderUnavailable("OpenAI Python SDK is not installed.") from error
            kwargs = {"api_key": self.api_key, "timeout": self.timeout}
            if self.base_url != "https://api.openai.com/v1":
                kwargs["base_url"] = self.base_url
            self._client = OpenAI(**kwargs)
        return self._client


class OptionalAPIKeyProvider(AIProviderStrategy):
    """Configured-but-deferred provider for future API-key-backed integrations."""

    def __init__(self, *, provider_name: AIProviderName, api_key: str | None, model: str) -> None:
        self._provider_name = provider_name
        self.api_key = api_key
        self.model = model

    @property
    def provider_name(self) -> AIProviderName:
        return self._provider_name

    @property
    def status(self) -> ProviderStatus:
        configured = bool(self.api_key)
        return ProviderStatus(
            provider=self.provider_name.value,
            available=False,
            configured=configured,
            model=self.model,
            message=(
                f"{self.provider_name.value.title()} is configured, but the runtime adapter is not enabled yet."
                if configured
                else f"{self.provider_name.value.title()} API key is not configured."
            ),
            health_source="adapter",
        )

    def generate(self, request: AIRequest) -> AIResponse:
        raise AIProviderUnavailable(f"{self.provider_name.value} adapter is not enabled.")


class GeminiFutureProvider(OptionalAPIKeyProvider, GeminiProviderStrategy):
    """Gemini placeholder that preserves the provider contract."""


class PerplexityFutureProvider(OptionalAPIKeyProvider, PerplexityProviderStrategy):
    """Perplexity placeholder that preserves the provider contract."""


class AIProviderManager:
    """Select providers from settings and fall back without crashing."""

    fallback_order = (
        AIProviderName.OLLAMA.value,
        AIProviderName.OPENAI.value,
        AIProviderName.GEMINI.value,
        AIProviderName.PERPLEXITY.value,
    )

    def __init__(self, providers: dict[str, AIProviderStrategy] | None = None) -> None:
        self._providers = providers or {}
        self._status_cache: dict[str, tuple[float, ProviderStatus]] = {}
        self._failed_until: dict[str, float] = {}
        self.status_ttl_seconds = 5.0
        self.failover_enabled = True
        self._fallback_order = list(self.fallback_order)

    def configure_failover(self, *, enabled: bool, order: list[str] | tuple[str, ...]) -> None:
        """Apply an allow-listed routing order without changing provider adapters."""
        registered = set(self._providers)
        normalized = [str(item) for item in order if str(item) in registered]
        self.failover_enabled = bool(enabled)
        self._fallback_order = normalized or list(self.fallback_order)

    def select(self, provider_name: AIProviderName | str) -> AIProviderStrategy:
        key = provider_name.value if isinstance(provider_name, AIProviderName) else str(provider_name)
        provider = self._providers.get(key)
        if provider and not self._temporarily_failed(key) and self.status(key).available:
            return provider
        if not self.failover_enabled:
            raise AIProviderUnavailable(f"AI provider '{key}' is unavailable and failover is disabled.")
        for fallback_key in self._fallback_order:
            provider = self._providers.get(fallback_key)
            if provider and not self._temporarily_failed(fallback_key) and self.status(fallback_key).available:
                return provider
        raise AIProviderUnavailable("No AI provider available.")

    def status(self, provider_name: str) -> ProviderStatus:
        cached = self._status_cache.get(str(provider_name))
        if cached and time.time() - cached[0] < self.status_ttl_seconds:
            return cached[1]
        provider = self._providers.get(str(provider_name))
        if provider is None:
            return ProviderStatus(
                provider=str(provider_name),
                available=False,
                configured=False,
                model="",
                message="Provider is not registered.",
            )
        status = getattr(provider, "status", None)
        if isinstance(status, ProviderStatus):
            self._status_cache[str(provider_name)] = (time.time(), status)
            return status
        fallback = ProviderStatus(
            provider=str(provider_name),
            available=False,
            configured=False,
            model="",
            message="Provider adapter does not expose health status.",
        )
        self._status_cache[str(provider_name)] = (time.time(), fallback)
        return fallback

    def all_statuses(self) -> dict[str, ProviderStatus]:
        return {name: self.status(name) for name in self._providers}

    @property
    def routing_policy(self) -> dict[str, object]:
        return {"enabled": self.failover_enabled, "order": list(self._fallback_order)}

    def test_connection(self, provider_name: str) -> ProviderStatus:
        key = str(provider_name)
        self._failed_until.pop(key, None)
        self._status_cache.pop(key, None)
        provider = self._providers.get(key)
        tester = getattr(provider, "test_connection", None) if provider is not None else None
        status = tester() if callable(tester) else self.status(key)
        self._status_cache[key] = (time.time(), status)
        return status

    def mark_unavailable(self, provider_name: str, *, retry_after: float = 10.0) -> None:
        """Temporarily avoid a failed provider so a configured fallback can run."""
        key = str(provider_name)
        self._failed_until[key] = time.time() + retry_after
        self._status_cache.pop(key, None)

    def _temporarily_failed(self, provider_name: str) -> bool:
        return self._failed_until.get(str(provider_name), 0.0) > time.time()


AIProviderRegistry = AIProviderManager


def build_ai_registry(config: dict) -> AIProviderManager:
    """Create configured provider adapters without requiring credentials."""

    ollama = OllamaHTTPProvider(
        endpoint=str(config.get("OLLAMA_ENDPOINT") or config.get("AI_OLLAMA_ENDPOINT") or "http://localhost:11434"),
        model=str(config.get("OLLAMA_MODEL") or config.get("AI_MODEL") or "qwen3:8b"),
        timeout=int(config.get("AI_TIMEOUT_SECONDS") or 60),
        keep_alive=str(config.get("OLLAMA_KEEP_ALIVE") or "10m"),
    )
    openai = OpenAISDKProvider(
        api_key=config.get("OPENAI_API_KEY") or config.get("AI_API_KEY"),
        model=str(config.get("OPENAI_MODEL") or "gpt-4.1-mini"),
        base_url=config.get("AI_BASE_URL"),
        timeout=int(config.get("AI_TIMEOUT_SECONDS") or 60),
    )
    gemini = GeminiFutureProvider(
        provider_name=AIProviderName.GEMINI,
        api_key=config.get("GEMINI_API_KEY"),
        model=str(config.get("GEMINI_MODEL") or "gemini-1.5-flash"),
    )
    perplexity = PerplexityFutureProvider(
        provider_name=AIProviderName.PERPLEXITY,
        api_key=config.get("PERPLEXITY_API_KEY"),
        model=str(config.get("PERPLEXITY_MODEL") or "sonar"),
    )
    return AIProviderManager(
        {
            AIProviderName.OLLAMA.value: ollama,
            AIProviderName.OPENAI.value: openai,
            AIProviderName.GEMINI.value: gemini,
            AIProviderName.PERPLEXITY.value: perplexity,
        }
    )


def messages(system: str, user: str) -> tuple[AIMessage, AIMessage]:
    """Convenience helper for provider-neutral message construction."""

    return (AIMessage(role="system", content=system), AIMessage(role="user", content=user))
