from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest
from sqlalchemy import select

from cyberinvestigator import create_app
from cyberinvestigator.infrastructure.database.models import CustodyEvent


def _archive_bytes() -> bytes:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("observed.txt", "Observed URL https://example.test/path")
    return payload.getvalue()


def test_evidence_lab_persists_verified_runs_artifacts_and_custody(tmp_path: Path) -> None:
    app = create_app(
        "testing",
        {
            "QUARANTINE_UPLOAD_FOLDER": str(tmp_path / "quarantine"),
            "UPLOAD_FOLDER": str(tmp_path / "incoming"),
        },
    )
    client = app.test_client()
    case = client.post("/api/v1/cases", json={"case_number": "LAB-1", "title": "Evidence lab"}).get_json()
    upload = client.post(
        "/api/v1/evidence",
        data={
            "case_id": case["id"],
            "evidence_number": "LAB-E-1",
            "source_description": "Controlled test archive",
            "file": (io.BytesIO(_archive_bytes()), "sample.zip"),
        },
        content_type="multipart/form-data",
    )
    assert upload.status_code == 201
    evidence = upload.get_json()
    assert Path(app.config["QUARANTINE_UPLOAD_FOLDER"], evidence["storage_path"]).is_file()

    analyzed = client.get(f"/api/v1/evidence/{evidence['id']}/analysis")
    assert analyzed.status_code == 200
    report = analyzed.get_json()["report"]
    assert report["evidence"]["integrity_verified"] is True
    assert report["observation_model"]["static_findings"].startswith("verified observations")
    assert report["observation_model"]["ai_explanation"].startswith("AI-generated")
    assert report["ai_explanation"]["provenance"] == "ai_generated_interpretation"

    record = client.get(f"/api/v1/evidence/{evidence['id']}/lab").get_json()
    assert record["analysis_runs"][0]["status"] == "completed"
    assert record["analysis_runs"][0]["integrity_verified"] is True
    assert {item["finding_type"] for item in record["verified_findings"]} >= {"file_signature", "entropy"}
    assert record["custody"][0]["event_type"] == "evidence.quarantined"
    assert record["custody"][-1]["event_type"] == "evidence.analysis.completed"
    assert record["sandbox"]["status"] == "unavailable"
    assert record["sandbox"]["submission_enabled"] is False

    workspace = client.get("/api/v1/evidence-lab").get_json()
    assert workspace["evidence_status"][0]["storage_state"] == "quarantined"
    assert workspace["analysis_results"][0]["status"] == "completed"
    artifact = workspace["artifacts"][0]
    assert artifact["name"] == "observed.txt"
    assert len(artifact["content_hash"]) == 64
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        custody = database.session.scalar(select(CustodyEvent))
        custody.details = "attempted mutation"
        with pytest.raises(ValueError, match="append-only"):
            database.session.commit()
        database.session.rollback()


def test_integrity_mismatch_fails_without_static_findings(tmp_path: Path) -> None:
    app = create_app(
        "testing",
        {
            "QUARANTINE_UPLOAD_FOLDER": str(tmp_path / "quarantine"),
            "UPLOAD_FOLDER": str(tmp_path / "incoming"),
        },
    )
    client = app.test_client()
    case = client.post("/api/v1/cases", json={"case_number": "LAB-2", "title": "Integrity"}).get_json()
    evidence = client.post(
        "/api/v1/evidence",
        json={
            "case_id": case["id"],
            "evidence_number": "LAB-E-2",
            "filename": "sample.bin",
            "content": "original",
        },
    ).get_json()
    custody_file = Path(app.config["QUARANTINE_UPLOAD_FOLDER"], evidence["storage_path"])
    custody_file.write_bytes(b"modified")

    response = client.get(f"/api/v1/evidence/{evidence['id']}/analysis")
    assert response.status_code == 400
    record = client.get(f"/api/v1/evidence/{evidence['id']}/lab").get_json()
    assert record["analysis_runs"][0]["status"] == "failed"
    assert record["analysis_runs"][0]["integrity_verified"] is False
    assert record["verified_findings"] == []
    assert record["custody"][-1]["event_type"] == "evidence.analysis.failed"


def test_evidence_lab_mobile_information_order_and_unavailable_provider() -> None:
    client = create_app("testing").test_client()
    html = client.get("/evidence").get_data(as_text=True)
    labels = ("Evidence Status", "Analysis Results", "Queue", "Artifacts")
    assert [html.index(label) for label in labels] == sorted(html.index(label) for label in labels)
    assert "evidence_lab.css" in html
    assert 'aria-live="polite"' in html
    assert client.get("/api/v1/evidence-lab").get_json()["sandbox"]["status"] == "unavailable"
