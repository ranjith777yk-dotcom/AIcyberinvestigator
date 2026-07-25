"""Trust boundary for future isolated evidence analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Protocol
from uuid import UUID


@dataclass(frozen=True, slots=True, kw_only=True)
class AnalysisRequest:
    """Provider-neutral request for analysis of one immutable evidence object."""

    evidence_id: UUID
    case_id: UUID
    storage_path: str
    sha256: str
    analyzer: str
    limits: Mapping[str, int] = field(default_factory=dict)


@dataclass(frozen=True, slots=True, kw_only=True)
class AnalysisResult:
    """Normalized result returned across the isolated analysis boundary."""

    status: str
    analyzer: str
    analyzer_version: str
    evidence_sha256: str
    findings: Mapping[str, object] = field(default_factory=dict)
    error_code: str | None = None


class AnalysisRunner(Protocol):
    """Run evidence analysis in an implementation-defined trust zone."""

    def analyze(self, request: AnalysisRequest) -> AnalysisResult:
        """Analyze evidence under explicit limits and return normalized findings."""
        ...
