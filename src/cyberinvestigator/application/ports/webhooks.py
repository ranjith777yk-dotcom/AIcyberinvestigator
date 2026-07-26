"""Prepared webhook contracts; no subscription or delivery adapter is active."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True, slots=True)
class WebhookEvent:
    """Versioned, non-secret event envelope for a future durable outbox."""

    id: UUID
    event_type: str
    occurred_at: datetime
    api_version: str
    resource_id: str
    data: dict[str, object]

    def canonical_bytes(self) -> bytes:
        document = asdict(self)
        document["id"] = str(self.id)
        document["occurred_at"] = self.occurred_at.isoformat()
        return json.dumps(document, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sign_webhook_payload(payload: bytes, secret: bytes) -> str:
    """Return the prepared HMAC-SHA256 signature format."""
    if len(secret) < 32:
        raise ValueError("Webhook signing secrets must contain at least 32 bytes.")
    return "sha256=" + hmac.new(secret, payload, hashlib.sha256).hexdigest()


def verify_webhook_signature(payload: bytes, signature: str, secret: bytes) -> bool:
    """Verify a prepared signature without exposing timing information."""
    expected = sign_webhook_payload(payload, secret)
    return hmac.compare_digest(expected, signature)
