"""CredentialNotFoundError: the credential or record a command targets is not on the lock."""

from __future__ import annotations

from .lock_rejected import LockRejectedError


class CredentialNotFoundError(LockRejectedError):
    """Raised when the credential or record the command targets is not stored on the lock."""
