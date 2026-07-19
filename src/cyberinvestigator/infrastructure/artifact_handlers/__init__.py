"""Non-executing artifact handler declarations."""

from cyberinvestigator.infrastructure.artifact_handlers.base import BaseArtifactHandler
from cyberinvestigator.infrastructure.artifact_handlers.handlers import (
    ArchiveArtifactHandler,
    EmailArtifactHandler,
    ExecutableArtifactHandler,
    ImageArtifactHandler,
    MemoryArtifactHandler,
    OfficeArtifactHandler,
    PCAPArtifactHandler,
    PDFArtifactHandler,
)

__all__ = [
    "ArchiveArtifactHandler",
    "BaseArtifactHandler",
    "EmailArtifactHandler",
    "ExecutableArtifactHandler",
    "ImageArtifactHandler",
    "MemoryArtifactHandler",
    "OfficeArtifactHandler",
    "PCAPArtifactHandler",
    "PDFArtifactHandler",
]
