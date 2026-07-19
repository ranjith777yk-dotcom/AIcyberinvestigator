"""Tests for fallback-safe AI investigation capabilities."""

from cyberinvestigator.domain.services.cybersecurity_ai import (
    ConversationMemoryStore,
    CybersecurityAnalysisEngine,
    InvestigationAssistant,
)


def test_analysis_extracts_iocs_mitre_sigma_and_score() -> None:
    engine = CybersecurityAnalysisEngine()

    result = engine.analyze_text("powershell -EncodedCommand AAAA contacted http://evil.example.com/a from 10.0.0.5")

    assert "10.0.0.5" in result.iocs["ipv4"]
    assert "http://evil.example.com/a" in result.iocs["url"]
    assert any(item["technique_id"] == "T1059.001" for item in result.mitre_attack)
    assert result.sigma
    assert result.threat_score > 0
    assert result.recommendations


def test_assistant_records_case_scoped_conversation_memory() -> None:
    assistant = InvestigationAssistant(CybersecurityAnalysisEngine(), ConversationMemoryStore())

    response = assistant.respond(
        message="Analyze suspicious domain bad.example.com",
        case_context={"case_id": "case-1", "case_number": "CASE-1", "evidence": [], "timeline": []},
    )

    assert "CASE-1" in response["reply"]
    assert len(response["memory"]) == 2
    assert response["analysis"]["iocs"]["domain"] == ["bad.example.com"]
