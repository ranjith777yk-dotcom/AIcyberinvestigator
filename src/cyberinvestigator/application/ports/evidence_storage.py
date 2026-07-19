"""Storage boundary for immutable, case-linked evidence bytes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import BinaryIO, Protocol
from uuid import UUID


@dataclass(frozen=True, slots=True)
class StoredEvidenceFile:
    """Metadata produced while safely storing an evidence stream."""

    storage_path: str
    size_bytes: int
    sha256: str
    media_type: str


class EvidenceStorage(Protocol):
    """Port for persistence of evidence bytes outside the database."""

    def store(
        self,
        *,
        case_id: UUID,
        filename: str,
        content: BinaryIO,
        media_type: str | None = None,
    ) -> StoredEvidenceFile:
        """Store one stream and return its content-derived metadata."""
        ...

    def remove(self, storage_path: str) -> None:
        """Remove a newly stored file only when safe compensation is required."""
        ...
