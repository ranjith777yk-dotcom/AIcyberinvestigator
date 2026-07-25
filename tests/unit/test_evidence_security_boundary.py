from __future__ import annotations

import json
from io import BytesIO
from uuid import uuid4

import pytest

from cyberinvestigator.infrastructure.evidence_storage import EvidenceFileLocator, LocalEvidenceStorage
from cyberinvestigator.infrastructure.security.audit import SecurityAuditEvent, StructuredAuditWriter
from cyberinvestigator.shared.exceptions import EvidenceStorageError


def test_new_evidence_is_size_bounded_and_partial_bytes_are_removed(tmp_path) -> None:
    storage = LocalEvidenceStorage(tmp_path / "quarantine", max_bytes=4)
    with pytest.raises(EvidenceStorageError, match="size limit"):
        storage.store(case_id=uuid4(), filename="hostile.bin", content=BytesIO(b"12345"))
    assert list((tmp_path / "quarantine").rglob("*.*")) == []


def test_locator_prefers_quarantine_and_supports_legacy_custody_files(tmp_path) -> None:
    case_id = uuid4()
    identifier = f"{case_id}/evidence.bin"
    quarantine = tmp_path / "quarantine"
    incoming = tmp_path / "incoming"
    legacy_file = incoming / identifier
    legacy_file.parent.mkdir(parents=True)
    legacy_file.write_bytes(b"legacy")
    locator = EvidenceFileLocator(quarantine, (incoming,))

    assert locator.resolve(identifier) == legacy_file.resolve()
    with pytest.raises(EvidenceStorageError):
        locator.resolve("../outside")


def test_locator_rejects_symlinked_custody_paths(tmp_path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "evidence.bin").write_bytes(b"hostile")
    quarantine = tmp_path / "quarantine"
    quarantine.mkdir()
    linked_case = quarantine / str(uuid4())
    try:
        linked_case.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Symbolic links are unavailable in this environment.")
    locator = EvidenceFileLocator(quarantine)
    with pytest.raises(EvidenceStorageError, match="symbolic link"):
        locator.resolve(f"{linked_case.name}/evidence.bin")


def test_structured_audit_writer_sanitizes_control_characters(tmp_path) -> None:
    writer = StructuredAuditWriter(tmp_path)
    writer.write(
        SecurityAuditEvent(
            timestamp=1.0,
            event="rbac.blocked\nforged",
            request_id="request",
            method="POST",
            path="/api/v1/evidence",
            status=403,
            user="analyst",
            role="user",
        )
    )
    lines = (tmp_path / "audit.log").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["event"] == "rbac.blockedforged"
    assert len(payload["event_hash"]) == 64
    assert writer.verify_integrity()["valid"] is True

    payload["event"] = "tampered"
    (tmp_path / "audit.log").write_text(json.dumps(payload) + "\n", encoding="utf-8")
    assert writer.verify_integrity()["valid"] is False
