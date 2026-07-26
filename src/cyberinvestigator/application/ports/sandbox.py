"""Trust boundary for future external dynamic-analysis providers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol
from uuid import UUID


@dataclass(frozen=True, slots=True)
class SandboxRequest:
    evidence_id: UUID
    case_id: UUID
    evidence_sha256: str
    storage_reference: str


@dataclass(frozen=True, slots=True)
class SandboxResult:
    status: str
    provider: str
    external_reference: str | None = None
    observations: Mapping[str, object] | None = None
    error_code: str | None = None


class SandboxAdapter(Protocol):
    identifier: str

    def availability(self) -> Mapping[str, object]:
        """Report configured capability without inventing provider health."""
        ...

    def submit(self, request: SandboxRequest) -> SandboxResult:
        """Submit by explicit adapter implementation outside the web process."""
        ...


class UnavailableSandboxAdapter:
    identifier = "unconfigured"

    def availability(self) -> Mapping[str, object]:
        return {
            "provider": self.identifier,
            "configured": False,
            "status": "unavailable",
            "submission_enabled": False,
            "reason": "No isolated sandbox adapter is configured.",
        }

    def submit(self, request: SandboxRequest) -> SandboxResult:
        del request
        return SandboxResult(status="unavailable", provider=self.identifier, error_code="adapter_unavailable")
