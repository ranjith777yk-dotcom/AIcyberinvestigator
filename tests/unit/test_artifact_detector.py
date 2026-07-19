"""Tests for bounded, non-analytical artifact identification."""

from __future__ import annotations

from io import BytesIO

import pytest

from cyberinvestigator.domain.services import (
    ArtifactDetector,
    ArtifactSource,
    DetectedArtifactType,
)
from cyberinvestigator.shared.exceptions import ArtifactInputError


@pytest.mark.parametrize(
    ("filename", "header", "expected_type", "expected_media_type"),
    [
        ("image.bin", b"\x89PNG\r\n\x1a\nrest", DetectedArtifactType.IMAGE, "image/png"),
        ("document.bin", b"%PDF-1.7", DetectedArtifactType.PDF, "application/pdf"),
        ("archive.bin", b"PK\x03\x04payload", DetectedArtifactType.ZIP, "application/zip"),
        ("archive.bin", b"Rar!\x1a\x07\x00payload", DetectedArtifactType.RAR, "application/vnd.rar"),
        ("archive.bin", b"7z\xbc\xaf'\x1cpayload", DetectedArtifactType.SEVEN_Z, "application/x-7z-compressed"),
        ("binary.bin", b"MZpayload", DetectedArtifactType.EXECUTABLE, "application/vnd.microsoft.portable-executable"),
        ("capture.bin", b"\xd4\xc3\xb2\xa1payload", DetectedArtifactType.PCAP, "application/vnd.tcpdump.pcap"),
        ("memory.bin", b"MDMPpayload", DetectedArtifactType.MEMORY_DUMP, "application/x-minidump"),
    ],
)
def test_detects_supported_magic_numbers(filename, header, expected_type, expected_media_type) -> None:
    """Known signatures are classified from the bounded header, regardless of filename."""
    result = ArtifactDetector().detect(ArtifactSource(filename=filename, content=header))

    assert result.artifact_type is expected_type
    assert result.media_type == expected_media_type
    assert result.classification_basis == ("magic number",)


def test_office_open_xml_is_distinguished_from_an_ordinary_zip() -> None:
    """A ZIP header plus an Office extension is metadata-classified as Office."""
    result = ArtifactDetector().detect(ArtifactSource(filename="report.docx", content=b"PK\x03\x04payload"))

    assert result.artifact_type is DetectedArtifactType.OFFICE
    assert result.classification_basis == ("magic number", "filename extension")


def test_detects_email_from_filename_without_inspecting_message_contents() -> None:
    """Email identification falls back to filename metadata when no magic number exists."""
    result = ArtifactDetector().detect(
        ArtifactSource(filename="message.eml", content=b"From: analyst@example.test\r\n")
    )

    assert result.artifact_type is DetectedArtifactType.EMAIL
    assert result.classification_basis == ("filename extension",)


def test_detector_restores_seekable_upload_stream_position() -> None:
    """Header detection does not consume a seekable upload stream needed by later storage."""
    source = BytesIO(b"%PDF-1.7 content")
    source.seek(2)

    ArtifactDetector().detect(ArtifactSource(filename="sample.pdf", content=source))

    assert source.tell() == 2


def test_detector_rejects_file_paths_in_filename_metadata() -> None:
    """A detector caller must provide a filename, rather than an ambiguous path."""
    with pytest.raises(ArtifactInputError):
        ArtifactDetector().detect(ArtifactSource(filename="folder/sample.pdf", content=b"%PDF-"))
