"""Abstract contract for non-executing artifact handlers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from cyberinvestigator.domain.services.artifact_engine import ArtifactType


class BaseArtifactHandler(ABC):
    """Declare an artifact handler's supported type and metadata formats.

    Implementations intentionally define no analysis, parsing, extraction, or
    file-access behavior. Those concerns belong to explicitly authorised future
    processing components.
    """

    @property
    @abstractmethod
    def handler_id(self) -> str:
        """Return the stable identifier for this handler declaration."""
        ...

    @property
    @abstractmethod
    def artifact_type(self) -> ArtifactType:
        """Return the artifact category represented by this handler."""
        ...

    @property
    @abstractmethod
    def supported_extensions(self) -> tuple[str, ...]:
        """Return declared filename extensions associated with this handler."""
        ...

    @property
    @abstractmethod
    def supported_media_types(self) -> tuple[str, ...]:
        """Return declared media types associated with this handler."""
        ...
