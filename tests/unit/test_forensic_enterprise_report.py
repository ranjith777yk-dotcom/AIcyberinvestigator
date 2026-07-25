from __future__ import annotations

import hashlib

import pytest

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
    assert report["evidence"]["integrity_verified"] is True
    assert report["evidence"]["stored_size_bytes"] == len(payload)


def test_forensic_analysis_refuses_custody_hash_mismatch(tmp_path) -> None:
    sample = tmp_path / "tampered.bin"
    sample.write_bytes(b"changed after registration")

    with pytest.raises(ValueError, match="integrity verification failed"):
        ForensicAnalyzer().analyze_path(
            sample,
            evidence_number="EV-TAMPER",
            original_filename="tampered.bin",
            sha256=hashlib.sha256(b"original bytes").hexdigest(),
        )


def test_forensic_analysis_handles_unsupported_opaque_bytes_without_fabricating_findings(tmp_path) -> None:
    payload = bytes(range(256))
    sample = tmp_path / "opaque.bin"
    sample.write_bytes(payload)

    result = ForensicAnalyzer().analyze_path(
        sample,
        evidence_number="EV-OPAQUE",
        original_filename="opaque.bin",
        sha256=hashlib.sha256(payload).hexdigest(),
    )

    assert result.report["root"]["file_signature"] == "Unknown"
    assert result.report["ioc_table"] == []
    assert result.report["evidence"]["integrity_verified"] is True
