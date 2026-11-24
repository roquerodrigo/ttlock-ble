"""LockRejectedError: the lock answered a command with a FAILED status."""

from __future__ import annotations

from ..constants import LockErrorCode
from .ttlock import TTLockError


class LockRejectedError(TTLockError):
    """Raised when the lock refuses a command; `error_code` is the byte it sent, if any."""

    def __init__(self, action: str, error_code: int | None) -> None:
        """Build the message from the refused `action` and the lock's error byte."""
        self.action = action
        self.error_code = error_code
        super().__init__(f"Failed to {action}: lock rejected the command {_describe(error_code)}")


def _describe(error_code: int | None) -> str:
    if error_code is None:
        return "without an error code"
    try:
        name = LockErrorCode(error_code).name
    except ValueError:
        return f"with error {error_code:#04x}"
    return f"with error {error_code:#04x} ({name})"
