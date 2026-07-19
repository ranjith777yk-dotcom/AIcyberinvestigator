"""Bounded, signature-based identification of forensic artifact files."""

from __future__ import annotations

import mimetypes
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePath
from typing import BinaryIO, Final

from cyberinvestigator.shared.exceptions import ArtifactInputError


class DetectedArtifactType(str, Enum):
    """Artifact categories identified without content analysis."""

    IMAGE = "image"
    PDF = "pdf"
    ZIP = "zip"
    RAR = "rar"
    SEVEN_Z = "7z"
    OFFICE = "office"
    EMAIL = "email"
    EXECUTABLE = "executable"
    PCAP = "pcap"
    MEMORY_DUMP = "memory_dump"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True, kw_only=True)
class ArtifactSource:
    """File metadata and a byte source used exclusively to read a short header."""

    filename: str
    content: bytes | BinaryIO | Path
    declared_media_type: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Artifact:
    """Structured identification result, with no parsed or extracted content."""

    filename: str
    artifact_type: DetectedArtifactType
    media_type: str
    format_name: str | None
    magic_number: str | None
    classification_basis: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Signature:
    """One deterministic signature rule."""

    value: bytes
    artifact_type: DetectedArtifactType
    format_name: str
    media_type: str


class ArtifactDetector:
    """Identify file headers, MIME metadata, and categories without analysis.

    At most :attr:`HEADER_SIZE` bytes are read. No container/document parsing,
    extraction, execution, or tool invocation is performed.
    """

    HEADER_SIZE: Final[int] = 64
    _SIGNATURES: Final[tuple[_Signature, ...]] = (
        _Signature(b"\x89PNG\r\n\x1a\n", DetectedArtifactType.IMAGE, "PNG image", "image/png"),
        _Signature(b"\xff\xd8\xff", DetectedArtifactType.IMAGE, "JPEG image", "image/jpeg"),
        _Signature(b"GIF87a", DetectedArtifactType.IMAGE, "GIF image", "image/gif"),
        _Signature(b"GIF89a", DetectedArtifactType.IMAGE, "GIF image", "image/gif"),
        _Signature(b"BM", DetectedArtifactType.IMAGE, "Bitmap image", "image/bmp"),
        _Signature(b"II*\x00", DetectedArtifactType.IMAGE, "TIFF image", "image/tiff"),
        _Signature(b"MM\x00*", DetectedArtifactType.IMAGE, "TIFF image", "image/tiff"),
        _Signature(b"%PDF-", DetectedArtifactType.PDF, "PDF document", "application/pdf"),
        _Signature(b"Rar!\x1a\x07\x00", DetectedArtifactType.RAR, "RAR archive", "application/vnd.rar"),
        _Signature(b"Rar!\x1a\x07\x01\x00", DetectedArtifactType.RAR, "RAR archive", "application/vnd.rar"),
        _Signature(b"7z\xbc\xaf'\x1c", DetectedArtifactType.SEVEN_Z, "7-Zip archive", "application/x-7z-compressed"),
        _Signature(
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
            DetectedArtifactType.OFFICE,
            "OLE compound document",
            "application/x-ole-storage",
        ),
        _Signature(
            b"MZ", DetectedArtifactType.EXECUTABLE, "PE executable", "application/vnd.microsoft.portable-executable"
        ),
        _Signature(b"\x7fELF", DetectedArtifactType.EXECUTABLE, "ELF executable", "application/x-elf"),
        _Signature(b"\xd4\xc3\xb2\xa1", DetectedArtifactType.PCAP, "PCAP capture", "application/vnd.tcpdump.pcap"),
        _Signature(b"\xa1\xb2\xc3\xd4", DetectedArtifactType.PCAP, "PCAP capture", "application/vnd.tcpdump.pcap"),
        _Signature(b"\x0a\x0d\x0d\x0a", DetectedArtifactType.PCAP, "PCAPNG capture", "application/x-pcapng"),
        _Signature(b"MDMP", DetectedArtifactType.MEMORY_DUMP, "Windows minidump", "application/x-minidump"),
    )
    _OFFICE_EXTENSIONS: Final[frozenset[str]] = frozenset(
        {".doc", ".docm", ".docx", ".odt", ".ods", ".odp", ".ppt", ".pptm", ".pptx", ".xls", ".xlsb", ".xlsm", ".xlsx"}
    )
    _EXTENSION_TYPES: Final[dict[str, DetectedArtifactType]] = {
        ".pdf": DetectedArtifactType.PDF,
        ".zip": DetectedArtifactType.ZIP,
        ".rar": DetectedArtifactType.RAR,
        ".7z": DetectedArtifactType.SEVEN_Z,
        ".eml": DetectedArtifactType.EMAIL,
        ".mbox": DetectedArtifactType.EMAIL,
        ".msg": DetectedArtifactType.EMAIL,
        ".exe": DetectedArtifactType.EXECUTABLE,
        ".dll": DetectedArtifactType.EXECUTABLE,
        ".elf": DetectedArtifactType.EXECUTABLE,
        ".msi": DetectedArtifactType.EXECUTABLE,
        ".so": DetectedArtifactType.EXECUTABLE,
        ".pcap": DetectedArtifactType.PCAP,
        ".pcapng": DetectedArtifactType.PCAP,
        ".cap": DetectedArtifactType.PCAP,
        ".dmp": DetectedArtifactType.MEMORY_DUMP,
        ".mdmp": DetectedArtifactType.MEMORY_DUMP,
        ".mem": DetectedArtifactType.MEMORY_DUMP,
        ".raw": DetectedArtifactType.MEMORY_DUMP,
    }

    def detect(self, source: ArtifactSource) -> Artifact:
        """Return a structured identification using no more than 64 source bytes."""
        filename = self._validate_filename(source.filename)
        header = self._read_header(source.content)
        extension = PurePath(filename).suffix.lower()
        signature = self._detect_signature(header)
        media_type = self._detect_media_type(filename, source.declared_media_type, signature)
        artifact_type, format_name, basis = self._classify(extension, media_type, signature)
        return Artifact(
            filename=filename,
            artifact_type=artifact_type,
            media_type=media_type,
            format_name=format_name,
            magic_number=header[:8].hex(" ").upper() if header else None,
            classification_basis=basis,
        )

    def _classify(
        self, extension: str, media_type: str, signature: _Signature | None
    ) -> tuple[DetectedArtifactType, str | None, tuple[str, ...]]:
        """Combine a magic number with non-content filename and MIME metadata."""
        extension_type = (
            DetectedArtifactType.OFFICE
            if extension in self._OFFICE_EXTENSIONS
            else self._EXTENSION_TYPES.get(extension)
        )
        if signature is not None:
            if signature.artifact_type is DetectedArtifactType.ZIP and extension_type is DetectedArtifactType.OFFICE:
                return DetectedArtifactType.OFFICE, "Office Open XML document", ("magic number", "filename extension")
            return signature.artifact_type, signature.format_name, ("magic number",)
        if extension_type is not None:
            return extension_type, self._display_name(extension_type), ("filename extension",)
        inferred_type = self._artifact_type_from_media_type(media_type)
        if inferred_type is not DetectedArtifactType.UNKNOWN:
            return inferred_type, self._display_name(inferred_type), ("MIME type",)
        return DetectedArtifactType.UNKNOWN, None, ("no supported identifier",)

    def _detect_signature(self, header: bytes) -> _Signature | None:
        """Match a known magic number without parsing the remainder of the file."""
        for signature in self._SIGNATURES:
            if header.startswith(signature.value):
                return signature
        if header.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
            return _Signature(b"PK", DetectedArtifactType.ZIP, "ZIP archive", "application/zip")
        if header.startswith(b"RIFF") and header[8:12] == b"WEBP":
            return _Signature(b"RIFF", DetectedArtifactType.IMAGE, "WebP image", "image/webp")
        return None

    @staticmethod
    def _detect_media_type(filename: str, declared_media_type: str | None, signature: _Signature | None) -> str:
        """Return declared MIME metadata, a filename-based type, or a signature fallback."""
        if declared_media_type and declared_media_type.strip():
            return declared_media_type.strip().lower()
        guessed, _ = mimetypes.guess_type(filename)
        if guessed and guessed != "application/octet-stream":
            return guessed
        return signature.media_type if signature else (guessed or "application/octet-stream")

    @staticmethod
    def _artifact_type_from_media_type(media_type: str) -> DetectedArtifactType:
        """Classify well-known MIME values without opening further file content."""
        if media_type.startswith("image/"):
            return DetectedArtifactType.IMAGE
        mappings = {
            "application/pdf": DetectedArtifactType.PDF,
            "application/zip": DetectedArtifactType.ZIP,
            "application/vnd.rar": DetectedArtifactType.RAR,
            "application/x-7z-compressed": DetectedArtifactType.SEVEN_Z,
            "message/rfc822": DetectedArtifactType.EMAIL,
            "application/vnd.ms-outlook": DetectedArtifactType.EMAIL,
            "application/vnd.tcpdump.pcap": DetectedArtifactType.PCAP,
            "application/x-pcapng": DetectedArtifactType.PCAP,
            "application/x-minidump": DetectedArtifactType.MEMORY_DUMP,
            "application/vnd.microsoft.portable-executable": DetectedArtifactType.EXECUTABLE,
        }
        if media_type.startswith("application/vnd.openxmlformats-officedocument.") or media_type.startswith(
            "application/vnd.ms-"
        ):
            return DetectedArtifactType.OFFICE
        return mappings.get(media_type, DetectedArtifactType.UNKNOWN)

    @staticmethod
    def _display_name(artifact_type: DetectedArtifactType) -> str:
        """Return a stable display name for metadata-only classification."""
        return artifact_type.value.replace("_", " ").upper()

    @classmethod
    def _read_header(cls, content: bytes | BinaryIO | Path) -> bytes:
        """Read a bounded header and restore seekable stream position afterward."""
        if isinstance(content, bytes):
            return content[: cls.HEADER_SIZE]
        try:
            if isinstance(content, Path):
                with content.open("rb") as source_file:
                    return source_file.read(cls.HEADER_SIZE)
            position = content.tell() if content.seekable() else None
            header = content.read(cls.HEADER_SIZE)
            if position is not None:
                content.seek(position)
        except (AttributeError, OSError) as error:
            raise ArtifactInputError("Artifact source could not provide a readable byte header.") from error
        if not isinstance(header, bytes):
            raise ArtifactInputError("Artifact source must yield bytes.")
        return header

    @staticmethod
    def _validate_filename(filename: str) -> str:
        """Require a non-empty filename without a directory path."""
        normalized = filename.strip()
        if not normalized or PurePath(normalized).name != normalized:
            raise ArtifactInputError("Artifact filename must be a non-empty filename without a path.")
        return normalized
