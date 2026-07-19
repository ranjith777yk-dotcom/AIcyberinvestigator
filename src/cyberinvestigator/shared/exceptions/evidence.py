"""Custom exceptions raised by evidence-management services."""


class EvidenceManagementError(Exception):
    """Base exception for evidence-management failures safe for application callers."""


class EvidenceValidationError(EvidenceManagementError):
    """Raised when evidence metadata or an uploaded file is invalid."""


class EvidenceNotFoundError(EvidenceManagementError):
    """Raised when an active evidence record cannot be found."""


class EvidenceConflictError(EvidenceManagementError):
    """Raised when evidence metadata violates a uniqueness constraint."""


class EvidenceStorageError(EvidenceManagementError):
    """Raised when uploaded evidence cannot be stored or compensated safely."""


class EvidencePersistenceError(EvidenceManagementError):
    """Raised when evidence metadata persistence cannot complete safely."""
