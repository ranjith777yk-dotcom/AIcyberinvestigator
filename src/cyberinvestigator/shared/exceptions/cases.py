"""Custom exceptions raised by case-management application services."""


class CaseManagementError(Exception):
    """Base exception for case-management failures safe to expose to callers."""


class CaseValidationError(CaseManagementError):
    """Raised when a case create or update request is invalid."""


class CaseNotFoundError(CaseManagementError):
    """Raised when an active case cannot be found by its identifier."""


class CaseConflictError(CaseManagementError):
    """Raised when a create or update operation violates case uniqueness."""


class CaseStateError(CaseManagementError):
    """Raised when an operation is invalid for the case lifecycle state."""


class CasePersistenceError(CaseManagementError):
    """Raised when case persistence cannot complete safely."""
