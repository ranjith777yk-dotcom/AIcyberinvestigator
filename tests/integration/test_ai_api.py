"""Integration tests for AI API fallback behavior."""

from cyberinvestigator import create_app


def test_ai_status_reports_fallback_when_key_missing() -> None:
    client = create_app("testing").test_client()

    response = client.get("/api/v1/ai/status")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["fallback_available"] is True
    assert payload["available"] is False


def test_ai_chat_never_requires_provider_key() -> None:
    client = create_app("testing").test_client()

    response = client.post(
        "/api/v1/ai/chat",
        json={"message": "Check 8.8.8.8 and powershell encodedcommand activity."},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["available"] is False
    assert payload["reply"]
    assert "8.8.8.8" in payload["analysis"]["iocs"]["ipv4"]


def test_ai_analyze_accepts_text() -> None:
    client = create_app("testing").test_client()

    response = client.post("/api/v1/ai/analyze", json={"text": "From: attacker@example.com\nSubject: phishing"})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["email_headers"]["from"] == "attacker@example.com"
    assert payload["threat_score"] >= 0


def test_ai_specialized_analysis_endpoints_fallback_safely() -> None:
    client = create_app("testing").test_client()

    assert client.post("/api/v1/ai/explain-ioc", json={"indicator": "8.8.8.8"}).status_code == 200
    assert client.post("/api/v1/ai/explain-malware", json={"text": "MZ suspicious loader"}).status_code == 200
    assert client.post("/api/v1/ai/analyze-log", json={"text": "failed powershell encodedcommand"}).status_code == 200
    assert client.post("/api/v1/ai/analyze-email-header", json={"text": "From: a@example.com"}).status_code == 200
    assert client.post("/api/v1/ai/timeline-summary", json={}).status_code == 200


def test_openai_provider_status_uses_configured_key_without_exposing_it() -> None:
    client = create_app("testing", {"AI_ENABLED": True, "AI_API_KEY": "test-secret-key"}).test_client()

    response = client.get("/api/v1/ai/status")

    assert response.status_code == 200
    text = response.get_data(as_text=True)
    payload = response.get_json()
    assert payload["available"] is True
    assert payload["configured"] is True
    assert "test-secret-key" not in text
