"""Explainable correlation orchestration over configured intelligence providers."""

from __future__ import annotations

from dataclasses import asdict

from cyberinvestigator.application.ports.threat_intelligence import (
    IntelligenceFinding,
    NormalizedIndicator,
    ThreatIntelligenceProvider,
)


class ThreatIntelligenceCorrelationEngine:
    def __init__(self, providers: tuple[ThreatIntelligenceProvider, ...] = ()) -> None:
        self._providers = providers

    @property
    def provider_names(self) -> tuple[str, ...]:
        return tuple(provider.provider_name for provider in self._providers)

    def correlate(self, indicators: list[NormalizedIndicator]) -> dict[str, object]:
        findings: list[IntelligenceFinding] = []
        errors: list[dict[str, str]] = []
        for indicator in indicators:
            for provider in self._providers:
                if not provider.supports(indicator.type):
                    continue
                try:
                    finding = provider.enrich(indicator)
                except Exception:
                    errors.append({"provider": provider.provider_name, "indicator": indicator.value})
                    continue
                if finding is not None:
                    findings.append(finding)
        matched = {(item.indicator.type.value, item.indicator.value) for item in findings}
        records = []
        for indicator in indicators:
            related = [item for item in findings if item.indicator == indicator]
            records.append(
                {
                    "type": indicator.type.value,
                    "value": indicator.value,
                    "original_value": indicator.original_value,
                    "status": "enriched" if related else "unknown",
                    "findings": [self._finding_json(item) for item in related],
                }
            )
        return {
            "indicators": records,
            "findings": [self._finding_json(item) for item in findings],
            "summary": {
                "total": len(indicators),
                "enriched": len(matched),
                "unknown": len(indicators) - len(matched),
                "providers_queried": len(self._providers),
            },
            "providers": list(self.provider_names),
            "errors": errors,
            "explainability": "Unknown means no configured provider returned a finding; it does not mean benign.",
            "graph": {
                "nodes": [
                    {"id": f"indicator:{item.type.value}:{item.value}", "type": "indicator", "label": item.value}
                    for item in indicators
                ],
                "edges": [],
            },
        }

    @staticmethod
    def _finding_json(finding: IntelligenceFinding) -> dict[str, object]:
        payload = asdict(finding)
        payload["indicator"] = {
            "type": finding.indicator.type.value,
            "value": finding.indicator.value,
            "original_value": finding.indicator.original_value,
        }
        payload["reputation"] = finding.reputation.value
        payload["retrieved_at"] = finding.retrieved_at.isoformat()
        payload["observed_at"] = finding.observed_at.isoformat() if finding.observed_at else None
        payload["attack_techniques"] = list(finding.attack_techniques)
        return payload
