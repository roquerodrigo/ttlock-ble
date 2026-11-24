"""ReplyTimeoutError: the lock did not answer a command in time."""

from __future__ import annotations

from .ttlock import TTLockError


class ReplyTimeoutError(TTLockError):
    """Raised when no reply to a command arrives before its deadline."""
