"""Application-wide exception taxonomy."""

from cyberinvestigator.shared.exceptions.artifacts import ArtifactDetectionError, ArtifactInputError
from cyberinvestigator.shared.exceptions.cases import (
    CaseConflictError,
    CaseManagementError,
    CaseNotFoundError,
    CasePersistenceError,
    CaseStateError,
    CaseValidationError,
)
from cyberinvestigator.shared.exceptions.evidence import (
    EvidenceConflictError,
    EvidenceManagementError,
    EvidenceNotFoundError,
    EvidencePersistenceError,
    EvidenceStorageError,
    EvidenceValidationError,
)

__all__ = [
    "CaseConflictError",
    "CaseManagementError",
    "CaseNotFoundError",
    "CasePersistenceError",
    "CaseStateError",
    "CaseValidationError",
    "EvidenceConflictError",
    "EvidenceManagementError",
    "EvidenceNotFoundError",
    "EvidencePersistenceError",
    "EvidenceStorageError",
    "EvidenceValidationError",
    "ArtifactDetectionError",
    "ArtifactInputError",
]
