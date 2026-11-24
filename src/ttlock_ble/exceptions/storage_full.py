"""StorageFullError: the lock has no free slot left for another credential."""

from __future__ import annotations

from .lock_rejected import LockRejectedError


class StorageFullError(LockRejectedError):
    """Raised when the lock has no free slot left for another credential."""
