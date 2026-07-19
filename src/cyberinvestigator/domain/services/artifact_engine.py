"""Metadata-only artifact classification and handler selection.

The engine does not open files, inspect bytes, parse containers, extract
content, or invoke handlers. It classifies only declared artifact metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import PurePath
from typing import ClassVar


class ArtifactType(str, Enum):
    """Artifact categories supported by the classification boundary."""

    ZIP = "zip"
    PDF = "pdf"
    IMAGE = "image"
    OFFICE = "office"
    EMAIL = "email"
    EXECUTABLE = "executable"
    PCAP = "pcap"
    MEMORY_DUMP = "memory_dump"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True, kw_only=True)
class ArtifactDescriptor:
    """Declared metadata used for classification without accessing a file."""

    filename: str
    media_type: str | None = None
    signature_identifier: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ArtifactHandler:
    """A handler selection descriptor; it does not execute any handler."""

    identifier: str
    artifact_type: ArtifactType
    display_name: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ArtifactClassification:
    """Classification result with a selected non-executing handler descriptor."""

    artifact_type: ArtifactType
    handler: ArtifactHandler
    classification_basis: str


class ArtifactEngine:
    """Classify supported artifact metadata and select a handler descriptor."""

    _EXTENSION_TYPES: ClassVar[dict[str, ArtifactType]] = {
        ".zip": ArtifactType.ZIP,
        ".7z": ArtifactType.ZIP,
        ".rar": ArtifactType.ZIP,
        ".tar": ArtifactType.ZIP,
        ".gz": ArtifactType.ZIP,
        ".pdf": ArtifactType.PDF,
        ".bmp": ArtifactType.IMAGE,
        ".gif": ArtifactType.IMAGE,
        ".heic": ArtifactType.IMAGE,
        ".jpeg": ArtifactType.IMAGE,
        ".jpg": ArtifactType.IMAGE,
        ".png": ArtifactType.IMAGE,
        ".tif": ArtifactType.IMAGE,
        ".tiff": ArtifactType.IMAGE,
        ".doc": ArtifactType.OFFICE,
        ".docm": ArtifactType.OFFICE,
        ".docx": ArtifactType.OFFICE,
        ".odp": ArtifactType.OFFICE,
        ".ods": ArtifactType.OFFICE,
        ".odt": ArtifactType.OFFICE,
        ".ppt": ArtifactType.OFFICE,
        ".pptm": ArtifactType.OFFICE,
        ".pptx": ArtifactType.OFFICE,
        ".xls": ArtifactType.OFFICE,
        ".xlsm": ArtifactType.OFFICE,
        ".xlsx": ArtifactType.OFFICE,
        ".eml": ArtifactType.EMAIL,
        ".mbox": ArtifactType.EMAIL,
        ".msg": ArtifactType.EMAIL,
        ".dll": ArtifactType.EXECUTABLE,
        ".elf": ArtifactType.EXECUTABLE,
        ".exe": ArtifactType.EXECUTABLE,
        ".msi": ArtifactType.EXECUTABLE,
        ".so": ArtifactType.EXECUTABLE,
        ".pcap": ArtifactType.PCAP,
        ".pcapng": ArtifactType.PCAP,
        ".cap": ArtifactType.PCAP,
        ".dmp": ArtifactType.MEMORY_DUMP,
        ".mem": ArtifactType.MEMORY_DUMP,
        ".raw": ArtifactType.MEMORY_DUMP,
    }
    _MEDIA_TYPE_TYPES: ClassVar[dict[str, ArtifactType]] = {
        "application/pdf": ArtifactType.PDF,
        "application/zip": ArtifactType.ZIP,
        "application/x-7z-compressed": ArtifactType.ZIP,
        "application/x-rar-compressed": ArtifactType.ZIP,
        "application/vnd.ms-outlook": ArtifactType.EMAIL,
        "application/vnd.tcpdump.pcap": ArtifactType.PCAP,
        "application/x-pcap": ArtifactType.PCAP,
        "application/x-dmp": ArtifactType.MEMORY_DUMP,
        "application/x-msdownload": ArtifactType.EXECUTABLE,
        "application/vnd.microsoft.portable-executable": ArtifactType.EXECUTABLE,
    }
    _HANDLERS: ClassVar[dict[ArtifactType, ArtifactHandler]] = {
        ArtifactType.ZIP: ArtifactHandler(
            identifier="archive", artifact_type=ArtifactType.ZIP, display_name="Archive Handler"
        ),
        ArtifactType.PDF: ArtifactHandler(identifier="pdf", artifact_type=ArtifactType.PDF, display_name="PDF Handler"),
        ArtifactType.IMAGE: ArtifactHandler(
            identifier="image", artifact_type=ArtifactType.IMAGE, display_name="Image Handler"
        ),
        ArtifactType.OFFICE: ArtifactHandler(
            identifier="office", artifact_type=ArtifactType.OFFICE, display_name="Office Handler"
        ),
        ArtifactType.EMAIL: ArtifactHandler(
            identifier="email", artifact_type=ArtifactType.EMAIL, display_name="Email Handler"
        ),
        ArtifactType.EXECUTABLE: ArtifactHandler(
            identifier="executable", artifact_type=ArtifactType.EXECUTABLE, display_name="Executable Handler"
        ),
        ArtifactType.PCAP: ArtifactHandler(
            identifier="pcap", artifact_type=ArtifactType.PCAP, display_name="PCAP Handler"
        ),
        ArtifactType.MEMORY_DUMP: ArtifactHandler(
            identifier="memory_dump", artifact_type=ArtifactType.MEMORY_DUMP, display_name="Memory Dump Handler"
        ),
        ArtifactType.UNKNOWN: ArtifactHandler(
            identifier="unknown", artifact_type=ArtifactType.UNKNOWN, display_name="Unclassified Artifact Handler"
        ),
    }

    def classify(self, artifact: ArtifactDescriptor) -> ArtifactClassification:
        """Detect the declared type and select its corresponding handler descriptor."""
        artifact_type, basis = self.detect_artifact_type(artifact)
        return ArtifactClassification(
            artifact_type=artifact_type,
            handler=self.select_handler(artifact_type),
            classification_basis=basis,
        )

    def detect_artifact_type(self, artifact: ArtifactDescriptor) -> tuple[ArtifactType, str]:
        """Determine an artifact type from declared metadata without file access."""
        extension = PurePath(artifact.filename).suffix.lower()
        if extension in self._EXTENSION_TYPES:
            return self._EXTENSION_TYPES[extension], "filename extension"

        media_type = (artifact.media_type or "").strip().lower()
        if media_type.startswith("image/"):
            return ArtifactType.IMAGE, "media type"
        if media_type in self._MEDIA_TYPE_TYPES:
            return self._MEDIA_TYPE_TYPES[media_type], "media type"

        signature_identifier = (artifact.signature_identifier or "").strip().lower()
        if signature_identifier in self._MEDIA_TYPE_TYPES:
            return self._MEDIA_TYPE_TYPES[signature_identifier], "declared signature identifier"
        return ArtifactType.UNKNOWN, "no supported declared metadata"

    def select_handler(self, artifact_type: ArtifactType) -> ArtifactHandler:
        """Return the non-executing handler descriptor for a classified type."""
        return self._HANDLERS[artifact_type]
