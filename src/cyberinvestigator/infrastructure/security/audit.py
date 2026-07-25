"""Structured, append-only security audit file output."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Lock

from cyberinvestigator.infrastructure.observability import redact_text


@dataclass(frozen=True, slots=True, kw_only=True)
class SecurityAuditEvent:
    """Normalized security event safe for operational log export."""

    timestamp: float
    event: str
    request_id: str | None
    method: str
    path: str
    status: int
    user: str
    role: str
    remote_address: str | None = None
    user_agent: str | None = None
    reason: str | None = None


class StructuredAuditWriter:
    """Append normalized JSON events without exposing arbitrary object values."""

    _MAX_TEXT = 1024

    def __init__(self, log_directory: Path) -> None:
        self._path = log_directory.resolve() / "audit.log"
        self._lock = Lock()
        self._previous_hash = self._last_hash()

    def write(self, event: SecurityAuditEvent) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            key: self._sanitize(value) if isinstance(value, str) else value for key, value in asdict(event).items()
        }
        payload["previous_hash"] = self._previous_hash
        canonical = json.dumps(payload, separators=(",", ":"), ensure_ascii=True, sort_keys=True)
        payload["event_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
        with self._lock, self._path.open("a", encoding="utf-8", newline="\n") as audit_file:
            audit_file.write(encoded + "\n")
            audit_file.flush()
            os.fsync(audit_file.fileno())
            self._previous_hash = str(payload["event_hash"])

    def verify_integrity(self) -> dict[str, object]:
        """Verify the append-only hash chain without modifying the audit file."""
        previous_hash: str | None = None
        checked = 0
        legacy_records = 0
        if not self._path.exists():
            return {"valid": True, "records_checked": 0, "last_hash": None}
        with self._lock, self._path.open("r", encoding="utf-8") as audit_file:
            for line_number, line in enumerate(audit_file, start=1):
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    return {"valid": False, "records_checked": checked, "failed_line": line_number}
                event_hash = payload.pop("event_hash", None)
                if event_hash is None:
                    if checked:
                        return {"valid": False, "records_checked": checked, "failed_line": line_number}
                    legacy_records += 1
                    continue
                if payload.get("previous_hash") != previous_hash:
                    return {"valid": False, "records_checked": checked, "failed_line": line_number}
                canonical = json.dumps(payload, separators=(",", ":"), ensure_ascii=True, sort_keys=True)
                if not isinstance(event_hash, str) or not hmac.compare_digest(
                    event_hash, hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                ):
                    return {"valid": False, "records_checked": checked, "failed_line": line_number}
                previous_hash = event_hash
                checked += 1
        return {
            "valid": True,
            "records_checked": checked,
            "legacy_unsealed_records": legacy_records,
            "last_hash": previous_hash,
        }

    def _last_hash(self) -> str | None:
        if not self._path.exists():
            return None
        last_hash = None
        try:
            with self._path.open("r", encoding="utf-8") as audit_file:
                for line in audit_file:
                    payload = json.loads(line)
                    last_hash = payload.get("event_hash")
        except (OSError, json.JSONDecodeError):
            return None
        return str(last_hash) if last_hash else None

    def _sanitize(self, value: str) -> str:
        redacted = redact_text(value)
        return "".join(character for character in redacted[: self._MAX_TEXT] if character >= " " or character == "\t")
