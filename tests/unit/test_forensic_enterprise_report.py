from __future__ import annotations

import hashlib

from cyberinvestigator.domain.services.forensic_analyzer import ForensicAnalyzer


def test_forensic_report_contains_enterprise_sections_and_correlations(tmp_path) -> None:
    payload = (
        b"MZ powershell -enc SQBFAFgA https://evil.example.test/path "
        b"analyst@example.test 192.0.2.44 flag{validated_artifact}"
    )
    sample = tmp_path / "sample.bin"
    sample.write_bytes(payload)
    result = ForensicAnalyzer().analyze_path(
        sample,
        evidence_number="EV-1",
        original_filename="sample.bin",
        sha256=hashlib.sha256(payload).hexdigest(),
    )

    report = result.report
    required = {
        "executive_summary",
        "technical_summary",
        "evidence_summary",
        "threat_assessment",
        "recovered_files",
        "recovered_artifacts",
        "ioc_table",
        "mitre_mapping",
        "yara_results",
        "sigma_results",
        "timeline_summary",
        "risk_score",
        "confidence_score",
        "recommendations",
        "appendix",
    }
    assert required <= report.keys()
    assert any(item["type"] == "URL" for item in report["ioc_table"])
    assert report["yara_results"]
    assert report["sigma_results"]
    artifact = report["recovered_artifacts"][0]
    assert {"artifact", "location", "confidence", "evidence_path", "validation", "why_identified"} <= artifact.keys()
