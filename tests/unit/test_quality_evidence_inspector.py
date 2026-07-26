from __future__ import annotations

import json
from pathlib import Path

from cyberinvestigator.infrastructure.quality_management import QualityEvidenceInspector


def test_quality_evidence_is_truthfully_unavailable_without_artifacts(tmp_path: Path) -> None:
    payload = QualityEvidenceInspector(tmp_path).workspace()

    assert payload["source"] == "generated_test_artifacts"
    assert payload["test_status"]["status"] == "unavailable"
    assert payload["coverage_summary"]["status"] == "unavailable"
    assert payload["security_findings"]["sast"]["status"] == "unavailable"
    assert payload["failed_runs"] == []


def test_quality_evidence_parses_real_tool_artifacts(tmp_path: Path) -> None:
    (tmp_path / "junit.xml").write_text(
        '<testsuites><testsuite name="unit" tests="3" failures="1" errors="0" skipped="1" time="1.25" /></testsuites>',
        encoding="utf-8",
    )
    (tmp_path / "coverage-summary.json").write_text(json.dumps({"totals": {"percent_covered": 73.5}}), encoding="utf-8")

    payload = QualityEvidenceInspector(tmp_path).workspace()

    assert payload["test_status"] == {
        "tests": 3,
        "failures": 1,
        "errors": 0,
        "skipped": 1,
        "duration_seconds": 1.25,
        "status": "failed",
    }
    assert payload["failed_runs"][0]["suite"] == "unit"
    assert payload["coverage_summary"]["data"]["totals"]["percent_covered"] == 73.5


def test_quality_evidence_rejects_invalid_reports(tmp_path: Path) -> None:
    (tmp_path / "junit.xml").write_text("<broken", encoding="utf-8")
    (tmp_path / "bandit-report.json").write_text("not-json", encoding="utf-8")

    payload = QualityEvidenceInspector(tmp_path).workspace()

    assert payload["test_status"]["status"] == "unavailable"
    assert payload["security_findings"]["sast"]["status"] == "unavailable"
