"""CloudError: raised by `TTLockCloud` for non-zero server errcode/HTTP failures."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping


class CloudError(RuntimeError):
    """Raised when the TTLock cloud returns a non-success response."""

    def __init__(self, body: Mapping[str, object]) -> None:
        """Capture the raw response body so callers can inspect `errorCode`."""
        self.body = body
        msg = body.get("errmsg") or body.get("description") or body.get("message") or str(body)
        super().__init__(f"TTLock cloud error: {msg}")
