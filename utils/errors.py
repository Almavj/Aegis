class AlmaError(Exception):
    """Base exception for all Alma framework errors."""

    def __init__(self, message: str, original: Exception | None = None) -> None:
        super().__init__(message)
        self.original = original


class ScanError(AlmaError):
    """Raised when scanning operations fail (timeout, unreachable, etc.)."""


class ExploitError(AlmaError):
    """Raised when an exploit module encounters a recoverable or fatal failure."""


class SessionError(AlmaError):
    """Raised when session management (connect, pivot, cleanup) fails."""


class PayloadError(AlmaError):
    """Raised during payload generation, encoding, or delivery."""


class C2Error(AlmaError):
    """Raised when C2 protocol framing, crypto, or multiplexing fails."""
