from datetime import datetime, timezone

import pytest

from cyberinvestigator.application.ports.threat_intelligence import (
    IndicatorReputation,
    IndicatorType,
    IntelligenceFinding,
    ThreatIntelligenceProvider,
    normalize_indicator,
)
from cyberinvestigator.domain.services.threat_intelligence import ThreatIntelligenceCorrelationEngine


class RecordedProvider(ThreatIntelligenceProvider):
    @property
    def provider_name(self) -> str:
        return "recorded-test-provider"

    def supports(self, indicator_type: IndicatorType) -> bool:
        return indicator_type is IndicatorType.DOMAIN

    def enrich(self, indicator):
        return IntelligenceFinding(
            provider=self.provider_name,
            indicator=indicator,
            reputation=IndicatorReputation.SUSPICIOUS,
            confidence=0.72,
            observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            reference="provider-record-42",
            summary="Returned by the configured test provider.",
            attack_techniques=("T1071.001",),
        )


def test_indicator_normalization_is_stable_and_rejects_malformed_values() -> None:
    assert normalize_indicator("domain", "Example.COM.").value == "example.com"
    assert normalize_indicator("url", "HTTPS://Example.COM/path?q=1#fragment").value == "https://example.com/path?q=1"
    assert normalize_indicator("ipv6", "2001:0db8::1").value == "2001:db8::1"
    with pytest.raises(ValueError):
        normalize_indicator("sha256", "not-a-hash")


def test_unknown_is_not_benign_when_no_provider_returns_a_finding() -> None:
    indicator = normalize_indicator("ipv4", "8.8.8.8")
    result = ThreatIntelligenceCorrelationEngine().correlate([indicator])
    assert result["indicators"][0]["status"] == "unknown"
    assert result["findings"] == []
    assert "does not mean benign" in result["explainability"]


def test_provider_reputation_and_confidence_remain_separate_and_traceable() -> None:
    indicator = normalize_indicator("domain", "example.com")
    result = ThreatIntelligenceCorrelationEngine((RecordedProvider(),)).correlate([indicator])
    finding = result["findings"][0]
    assert finding["reputation"] == "suspicious"
    assert finding["confidence"] == 0.72
    assert finding["reference"] == "provider-record-42"
    assert finding["attack_techniques"] == ["T1071.001"]
