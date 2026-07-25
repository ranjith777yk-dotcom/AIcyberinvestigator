"""Report generation and export integration tests."""

from sqlalchemy import select

from cyberinvestigator import create_app
from cyberinvestigator.infrastructure.database.models import AuditLog


def test_report_export_contains_ai_summary_envelope() -> None:
    client = create_app("testing").test_client()
    case = client.post(
        "/api/v1/cases",
        json={"case_number": "REPORT-EXPORT-1", "title": "Report Export", "severity": "medium"},
    ).get_json()

    report_response = client.post(
        "/api/v1/reports",
        json={"case_id": case["id"], "report_type": "technical", "title": "Exportable Report"},
    )
    assert report_response.status_code == 201
    report_id = report_response.get_json()["id"]

    detail = client.get(f"/api/v1/reports/{report_id}")
    export = client.get(f"/api/v1/reports/{report_id}/export")

    assert detail.status_code == 200
    assert export.status_code == 200
    content = detail.get_json()["content"]
    assert content["ai_summary"]["available"] is False
    assert content["schema_version"] == "2.0"
    assert content["threat_score"] is None
    assert content["traceability"]["finding_sources_complete"] is True
    assert content["authorship"]["ai_explanation"].startswith("AI-generated")
    assert "attachment" in export.headers["Content-Disposition"]

    updated = client.patch(
        f"/api/v1/reports/{report_id}",
        json={"investigator_notes": "Validated by the assigned investigator.", "status": "approved"},
    )
    assert updated.status_code == 200
    updated_payload = updated.get_json()
    assert updated_payload["content"]["investigator_notes"][0]["authorship"] == "investigator"
    assert updated_payload["content"]["review"]["status"] == "approved"
    assert updated_payload["content"]["review"]["digital_signature"] is None

    pdf = client.get(f"/api/v1/reports/{report_id}/export?format=pdf")
    docx = client.get(f"/api/v1/reports/{report_id}/export?format=docx")
    assert pdf.status_code == 200
    assert pdf.data.startswith(b"%PDF")
    assert docx.status_code == 200
    assert docx.data.startswith(b"PK")

    app = client.application
    with app.app_context():
        database = app.extensions["cyberinvestigator_database"]
        actions = set(
            database.session.scalars(select(AuditLog.action).where(AuditLog.affected_object == f"report:{report_id}"))
        )
        assert {"report.generation.requested", "report.approved", "report.exported"}.issubset(actions)
