from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from cyberinvestigator.application.ports.webhooks import (
    WebhookEvent,
    sign_webhook_payload,
    verify_webhook_signature,
)


def test_webhook_envelope_serialization_and_signature_are_deterministic() -> None:
    event = WebhookEvent(
        id=UUID("11111111-1111-1111-1111-111111111111"),
        event_type="case.updated",
        occurred_at=datetime(2026, 7, 26, tzinfo=UTC),
        api_version="v1",
        resource_id="case-1",
        data={"status": "active"},
    )
    secret = b"s" * 32
    payload = event.canonical_bytes()
    signature = sign_webhook_payload(payload, secret)

    assert signature.startswith("sha256=")
    assert verify_webhook_signature(payload, signature, secret)
    assert not verify_webhook_signature(payload + b" ", signature, secret)


def test_webhook_signing_rejects_short_secrets() -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        sign_webhook_payload(b"payload", b"short")
