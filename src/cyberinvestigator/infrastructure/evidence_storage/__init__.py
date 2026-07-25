"""Filesystem-backed evidence storage adapters."""

from cyberinvestigator.infrastructure.evidence_storage.local import LocalEvidenceStorage
from cyberinvestigator.infrastructure.evidence_storage.locator import EvidenceFileLocator

__all__ = ["EvidenceFileLocator", "LocalEvidenceStorage"]
