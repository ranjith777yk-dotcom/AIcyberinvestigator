from __future__ import annotations

from cyberinvestigator import create_app
from cyberinvestigator.infrastructure.quality_management import QualityEvidenceInspector


def test_quality_api_is_admin_only_and_reports_unavailable_evidence(tmp_path) -> None:
    app = create_app("testing")
    app.extensions["cyberinvestigator_quality_inspector"] = QualityEvidenceInspector(tmp_path)
    client = app.test_client()

    denied = client.get("/api/v1/admin/quality", headers={"X-CI-Role": "user"})
    assert denied.status_code == 403

    response = client.get("/api/v1/admin/quality")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["source"] == "generated_test_artifacts"
    assert payload["test_status"]["status"] == "unavailable"


def test_quality_workspace_is_responsive_and_evidence_driven() -> None:
    response = create_app("testing").test_client().get("/admin/quality")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    for marker in (
        "Testing, Quality Assurance &amp; Security Validation",
        "Test Status",
        "Failed Runs",
        "Security Findings",
        "Coverage Summary",
        "quality_workspace.css",
        "quality_workspace.js",
    ):
        assert marker in html
