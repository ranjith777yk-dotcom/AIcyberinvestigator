"""Report generation and export integration tests."""

from cyberinvestigator import create_app


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
    assert detail.get_json()["content"]["ai_summary"]["available"] is False
    assert "attachment" in export.headers["Content-Disposition"]
