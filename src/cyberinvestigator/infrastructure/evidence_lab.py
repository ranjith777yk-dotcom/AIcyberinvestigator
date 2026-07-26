"""Modular, non-executing evidence-lab analysis orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Final

from cyberinvestigator.domain.services.forensic_analyzer import ForensicAnalyzer


@dataclass(frozen=True, slots=True)
class LabAnalysisResult:
    summary: str
    report: dict[str, object]
    modules: tuple[dict[str, object], ...]
    findings: tuple[dict[str, object], ...]
    artifacts: tuple[dict[str, object], ...]


class EvidenceLabAnalyzer:
    """Normalize bounded static modules while preserving the established analyzer."""

    IDENTIFIER: Final[str] = "cyberinvestigator.static"
    VERSION: Final[str] = "1"
    MODULES: Final[tuple[str, ...]] = (
        "sha256_integrity",
        "file_signature",
        "archive_metadata",
        "strings_and_indicators",
    )

    def __init__(self, analyzer: ForensicAnalyzer | None = None) -> None:
        self._analyzer = analyzer or ForensicAnalyzer()

    def analyze(
        self,
        path: Path,
        *,
        evidence_number: str,
        original_filename: str,
        sha256: str,
        progress: Callable[[int, str], None] | None = None,
    ) -> LabAnalysisResult:
        result = self._analyzer.analyze_path(
            path,
            evidence_number=evidence_number,
            original_filename=original_filename,
            sha256=sha256,
            progress=progress,
        )
        root = result.report.get("root")
        root_node = root if isinstance(root, dict) else {}
        modules = tuple(
            {"identifier": identifier, "status": "completed", "execution": "non_executing_static"}
            for identifier in self.MODULES
        )
        findings: list[dict[str, object]] = []
        signature = root_node.get("file_signature")
        if signature:
            findings.append({"finding_type": "file_signature", "value": str(signature)})
        entropy = root_node.get("entropy")
        if entropy is not None:
            findings.append({"finding_type": "entropy", "value": str(entropy)})
        iocs = result.report.get("ioc_table")
        if isinstance(iocs, list):
            for indicator in iocs[:200]:
                if not isinstance(indicator, dict):
                    continue
                indicator_type = str(indicator.get("type") or "indicator")
                value = indicator.get("value")
                if value:
                    findings.append({"finding_type": f"ioc.{indicator_type}", "value": str(value)})
        artifacts = tuple(self._child_artifacts(root_node))
        result.report["analysis_modules"] = list(modules)
        result.report["observation_model"] = {
            "static_findings": "verified observations from quarantined bytes",
            "ai_explanation": "AI-generated interpretation; not a verified forensic observation",
        }
        return LabAnalysisResult(
            summary=result.summary,
            report=result.report,
            modules=modules,
            findings=tuple(findings),
            artifacts=artifacts,
        )

    def _child_artifacts(self, node: dict[str, object], prefix: str = "") -> list[dict[str, object]]:
        artifacts: list[dict[str, object]] = []
        children = node.get("children")
        if not isinstance(children, list):
            return artifacts
        for child in children:
            if not isinstance(child, dict) or child.get("error"):
                continue
            name = str(child.get("name") or "embedded-artifact")
            location = f"{prefix}/{name}".lstrip("/")
            artifacts.append(
                {
                    "name": name,
                    "source_location": location,
                    "content_hash": str(child.get("sha256")) if child.get("sha256") else None,
                    "artifact_type": str(child.get("file_signature") or "unknown"),
                }
            )
            artifacts.extend(self._child_artifacts(child, location))
        return artifacts
