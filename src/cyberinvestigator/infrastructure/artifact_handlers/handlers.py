"""Concrete, non-executing artifact handler declarations."""

from __future__ import annotations

from typing import ClassVar

from cyberinvestigator.domain.services.artifact_engine import ArtifactType
from cyberinvestigator.infrastructure.artifact_handlers.base import BaseArtifactHandler


class ImageArtifactHandler(BaseArtifactHandler):
    """Declare support for image artifacts without opening image files."""

    HANDLER_ID: ClassVar[str] = "image"
    ARTIFACT_TYPE: ClassVar[ArtifactType] = ArtifactType.IMAGE
    SUPPORTED_EXTENSIONS: ClassVar[tuple[str, ...]] = (
        ".bmp",
        ".gif",
        ".heic",
        ".jpeg",
        ".jpg",
        ".png",
        ".tif",
        ".tiff",
    )
    SUPPORTED_MEDIA_TYPES: ClassVar[tuple[str, ...]] = (
        "image/bmp",
        "image/gif",
        "image/heic",
        "image/jpeg",
        "image/png",
        "image/tiff",
    )

    @property
    def handler_id(self) -> str:
        """Return the stable image handler identifier."""
        return self.HANDLER_ID

    @property
    def artifact_type(self) -> ArtifactType:
        """Return the image artifact category."""
        return self.ARTIFACT_TYPE

    @property
    def supported_extensions(self) -> tuple[str, ...]:
        """Return supported image extensions."""
        return self.SUPPORTED_EXTENSIONS

    @property
    def supported_media_types(self) -> tuple[str, ...]:
        """Return supported image media types."""
        return self.SUPPORTED_MEDIA_TYPES


class ArchiveArtifactHandler(BaseArtifactHandler):
    """Declare support for archive artifacts without opening containers."""

    HANDLER_ID: ClassVar[str] = "archive"
    ARTIFACT_TYPE: ClassVar[ArtifactType] = ArtifactType.ZIP
    SUPPORTED_EXTENSIONS: ClassVar[tuple[str, ...]] = (".7z", ".gz", ".rar", ".tar", ".zip")
    SUPPORTED_MEDIA_TYPES: ClassVar[tuple[str, ...]] = (
        "application/zip",
        "application/x-7z-compressed",
        "application/x-rar-compressed",
    )

    @property
    def handler_id(self) -> str:
        """Return the stable archive handler identifier."""
        return self.HANDLER_ID

    @property
    def artifact_type(self) -> ArtifactType:
        """Return the archive artifact category."""
        return self.ARTIFACT_TYPE

    @property
    def supported_extensions(self) -> tuple[str, ...]:
        """Return supported archive extensions."""
        return self.SUPPORTED_EXTENSIONS

    @property
    def supported_media_types(self) -> tuple[str, ...]:
        """Return supported archive media types."""
        return self.SUPPORTED_MEDIA_TYPES


class PDFArtifactHandler(BaseArtifactHandler):
    """Declare support for PDF artifacts without parsing documents."""

    HANDLER_ID: ClassVar[str] = "pdf"
    ARTIFACT_TYPE: ClassVar[ArtifactType] = ArtifactType.PDF
    SUPPORTED_EXTENSIONS: ClassVar[tuple[str, ...]] = (".pdf",)
    SUPPORTED_MEDIA_TYPES: ClassVar[tuple[str, ...]] = ("application/pdf",)

    @property
    def handler_id(self) -> str:
        """Return the stable PDF handler identifier."""
        return self.HANDLER_ID

    @property
    def artifact_type(self) -> ArtifactType:
        """Return the PDF artifact category."""
        return self.ARTIFACT_TYPE

    @property
    def supported_extensions(self) -> tuple[str, ...]:
        """Return supported PDF extensions."""
        return self.SUPPORTED_EXTENSIONS

    @property
    def supported_media_types(self) -> tuple[str, ...]:
        """Return supported PDF media types."""
        return self.SUPPORTED_MEDIA_TYPES


class ExecutableArtifactHandler(BaseArtifactHandler):
    """Declare support for executable artifacts without inspecting binaries."""

    HANDLER_ID: ClassVar[str] = "executable"
    ARTIFACT_TYPE: ClassVar[ArtifactType] = ArtifactType.EXECUTABLE
    SUPPORTED_EXTENSIONS: ClassVar[tuple[str, ...]] = (".dll", ".elf", ".exe", ".msi", ".so")
    SUPPORTED_MEDIA_TYPES: ClassVar[tuple[str, ...]] = (
        "application/vnd.microsoft.portable-executable",
        "application/x-msdownload",
    )

    @property
    def handler_id(self) -> str:
        """Return the stable executable handler identifier."""
        return self.HANDLER_ID

    @property
    def artifact_type(self) -> ArtifactType:
        """Return the executable artifact category."""
        return self.ARTIFACT_TYPE

    @property
    def supported_extensions(self) -> tuple[str, ...]:
        """Return supported executable extensions."""
        return self.SUPPORTED_EXTENSIONS

    @property
    def supported_media_types(self) -> tuple[str, ...]:
        """Return supported executable media types."""
        return self.SUPPORTED_MEDIA_TYPES


class OfficeArtifactHandler(BaseArtifactHandler):
    """Declare support for Office artifacts without parsing documents."""

    HANDLER_ID: ClassVar[str] = "office"
    ARTIFACT_TYPE: ClassVar[ArtifactType] = ArtifactType.OFFICE
    SUPPORTED_EXTENSIONS: ClassVar[tuple[str, ...]] = (
        ".doc",
        ".docm",
        ".docx",
        ".odp",
        ".ods",
        ".odt",
        ".ppt",
        ".pptm",
        ".pptx",
        ".xls",
        ".xlsm",
        ".xlsx",
    )
    SUPPORTED_MEDIA_TYPES: ClassVar[tuple[str, ...]] = (
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
    )

    @property
    def handler_id(self) -> str:
        """Return the stable Office handler identifier."""
        return self.HANDLER_ID

    @property
    def artifact_type(self) -> ArtifactType:
        """Return the Office artifact category."""
        return self.ARTIFACT_TYPE

    @property
    def supported_extensions(self) -> tuple[str, ...]:
        """Return supported Office extensions."""
        return self.SUPPORTED_EXTENSIONS

    @property
    def supported_media_types(self) -> tuple[str, ...]:
        """Return supported Office media types."""
        return self.SUPPORTED_MEDIA_TYPES


class EmailArtifactHandler(BaseArtifactHandler):
    """Declare support for email artifacts without parsing messages."""

    HANDLER_ID: ClassVar[str] = "email"
    ARTIFACT_TYPE: ClassVar[ArtifactType] = ArtifactType.EMAIL
    SUPPORTED_EXTENSIONS: ClassVar[tuple[str, ...]] = (".eml", ".mbox", ".msg")
    SUPPORTED_MEDIA_TYPES: ClassVar[tuple[str, ...]] = (
        "application/mbox",
        "application/vnd.ms-outlook",
        "message/rfc822",
    )

    @property
    def handler_id(self) -> str:
        """Return the stable email handler identifier."""
        return self.HANDLER_ID

    @property
    def artifact_type(self) -> ArtifactType:
        """Return the email artifact category."""
        return self.ARTIFACT_TYPE

    @property
    def supported_extensions(self) -> tuple[str, ...]:
        """Return supported email extensions."""
        return self.SUPPORTED_EXTENSIONS

    @property
    def supported_media_types(self) -> tuple[str, ...]:
        """Return supported email media types."""
        return self.SUPPORTED_MEDIA_TYPES


class PCAPArtifactHandler(BaseArtifactHandler):
    """Declare support for PCAP artifacts without parsing traffic."""

    HANDLER_ID: ClassVar[str] = "pcap"
    ARTIFACT_TYPE: ClassVar[ArtifactType] = ArtifactType.PCAP
    SUPPORTED_EXTENSIONS: ClassVar[tuple[str, ...]] = (".cap", ".pcap", ".pcapng")
    SUPPORTED_MEDIA_TYPES: ClassVar[tuple[str, ...]] = ("application/vnd.tcpdump.pcap", "application/x-pcap")

    @property
    def handler_id(self) -> str:
        """Return the stable PCAP handler identifier."""
        return self.HANDLER_ID

    @property
    def artifact_type(self) -> ArtifactType:
        """Return the PCAP artifact category."""
        return self.ARTIFACT_TYPE

    @property
    def supported_extensions(self) -> tuple[str, ...]:
        """Return supported PCAP extensions."""
        return self.SUPPORTED_EXTENSIONS

    @property
    def supported_media_types(self) -> tuple[str, ...]:
        """Return supported PCAP media types."""
        return self.SUPPORTED_MEDIA_TYPES


class MemoryArtifactHandler(BaseArtifactHandler):
    """Declare support for memory dumps without reading memory data."""

    HANDLER_ID: ClassVar[str] = "memory_dump"
    ARTIFACT_TYPE: ClassVar[ArtifactType] = ArtifactType.MEMORY_DUMP
    SUPPORTED_EXTENSIONS: ClassVar[tuple[str, ...]] = (".dmp", ".mem", ".raw")
    SUPPORTED_MEDIA_TYPES: ClassVar[tuple[str, ...]] = ("application/x-dmp", "application/x-memory-dump")

    @property
    def handler_id(self) -> str:
        """Return the stable memory handler identifier."""
        return self.HANDLER_ID

    @property
    def artifact_type(self) -> ArtifactType:
        """Return the memory-dump artifact category."""
        return self.ARTIFACT_TYPE

    @property
    def supported_extensions(self) -> tuple[str, ...]:
        """Return supported memory-dump extensions."""
        return self.SUPPORTED_EXTENSIONS

    @property
    def supported_media_types(self) -> tuple[str, ...]:
        """Return supported memory-dump media types."""
        return self.SUPPORTED_MEDIA_TYPES
