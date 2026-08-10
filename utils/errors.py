class AegisError(Exception):
    """Base exception for all Aegis framework errors."""

    def __init__(self, message: str, original: Exception | None = None) -> None:
        super().__init__(message)
        self.original = original


class ScanError(AegisError):
    """Raised when scanning operations fail (timeout, unreachable, etc.)."""


class ExploitError(AegisError):
    """Raised when an exploit module encounters a recoverable or fatal failure."""


class SessionError(AegisError):
    """Raised when session management (connect, pivot, cleanup) fails."""


class PayloadError(AegisError):
    """Raised during payload generation, encoding, or delivery."""


class C2Error(AegisError):
    """Raised when C2 protocol framing, crypto, or multiplexing fails."""
