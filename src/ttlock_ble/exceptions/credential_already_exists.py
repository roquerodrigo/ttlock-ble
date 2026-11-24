"""CredentialAlreadyExistsError: the credential being added is already stored on the lock."""

from __future__ import annotations

from .lock_rejected import LockRejectedError


class CredentialAlreadyExistsError(LockRejectedError):
    """Raised when the credential being added is already stored on the lock."""
