from __future__ import annotations

from pathlib import Path

from cyberinvestigator import create_app


def test_api_registered_evidence_is_preserved_in_quarantine(tmp_path) -> None:
    app = create_app(
        "testing",
        {
            "UPLOAD_FOLDER": str(tmp_path / "incoming"),
            "QUARANTINE_UPLOAD_FOLDER": str(tmp_path / "quarantine"),
        },
    )
    client = app.test_client()
    case = client.post("/api/v1/cases", json={"case_number": "Q-001", "title": "Quarantine"}).get_json()
    response = client.post(
        "/api/v1/evidence",
        json={
            "case_id": case["id"],
            "evidence_number": "EV-Q1",
            "filename": "untrusted.bin",
            "content": "untrusted bytes",
        },
    )
    assert response.status_code == 201
    evidence = response.get_json()
    assert (Path(app.config["QUARANTINE_UPLOAD_FOLDER"]) / evidence["storage_path"]).is_file()
    assert not (Path(app.config["UPLOAD_FOLDER"]) / evidence["storage_path"]).exists()
