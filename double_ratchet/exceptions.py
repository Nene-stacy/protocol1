"""Custom exceptions for the Double Ratchet library."""


class DoubleRatchetError(Exception):
    """Base exception for Double Ratchet errors."""


class DecryptionError(DoubleRatchetError):
    """Raised when message decryption fails (bad key, corrupted ciphertext)."""


class AuthenticationError(DoubleRatchetError):
    """Raised when AEAD authentication tag verification fails."""


class ReplayAttackError(DoubleRatchetError):
    """Raised when a duplicate message index is detected."""


class MaxSkipExceededError(DoubleRatchetError):
    """Raised when skipped message key limit is exceeded (potential DoS)."""


class SessionNotFoundError(DoubleRatchetError):
    """Raised when a session cannot be found in the store."""
