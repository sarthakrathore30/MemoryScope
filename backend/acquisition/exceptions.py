"""Custom exceptions for the Acquisition module (FR-1, FR-2, FR-3)."""


class AcquisitionError(Exception):
    """Base class for all acquisition-related errors."""


class UnsupportedFormatError(AcquisitionError):
    """Raised when the uploaded file extension/type is not a supported memory image format."""


class CorruptedImageError(AcquisitionError):
    """Raised when the uploaded file fails basic integrity checks (e.g. truncated, empty)."""


class ProfileDetectionError(AcquisitionError):
    """Raised when the OS profile of a memory image cannot be determined."""
