"""Custom exceptions for safe artifact identification."""


class ArtifactDetectionError(Exception):
    """Base exception for artifact-identification failures."""


class ArtifactInputError(ArtifactDetectionError):
    """Raised when an artifact source cannot provide a valid header."""
