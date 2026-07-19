"""Unit tests for metadata-only artifact classification."""

import pytest

from cyberinvestigator.domain.services import ArtifactDescriptor, ArtifactEngine, ArtifactType


@pytest.mark.parametrize(
    ("filename", "expected_type"),
    [
        ("sample.zip", ArtifactType.ZIP),
        ("sample.pdf", ArtifactType.PDF),
        ("sample.png", ArtifactType.IMAGE),
        ("sample.docx", ArtifactType.OFFICE),
        ("sample.eml", ArtifactType.EMAIL),
        ("sample.exe", ArtifactType.EXECUTABLE),
        ("sample.pcapng", ArtifactType.PCAP),
        ("sample.dmp", ArtifactType.MEMORY_DUMP),
    ],
)
def test_classifies_supported_filename_extensions(filename: str, expected_type: ArtifactType) -> None:
    """Each supported artifact category is classified from declared metadata."""
    result = ArtifactEngine().classify(ArtifactDescriptor(filename=filename))

    assert result.artifact_type is expected_type
    assert result.classification_basis == "filename extension"


def test_unknown_artifact_uses_non_executing_fallback_handler() -> None:
    """Unsupported metadata returns the unknown handler descriptor."""
    result = ArtifactEngine().classify(ArtifactDescriptor(filename="sample.unknown"))

    assert result.artifact_type is ArtifactType.UNKNOWN
    assert result.handler.identifier == "unknown"
