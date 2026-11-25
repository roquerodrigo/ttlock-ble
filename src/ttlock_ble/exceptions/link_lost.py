"""LinkLostError: the lock dropped the BLE link while a command waited for its reply."""

from __future__ import annotations

from .reply_timeout import ReplyTimeoutError


class LinkLostError(ReplyTimeoutError):
    """Raised as soon as the lock drops the BLE link before answering a command.

    No reply can arrive on a dropped link, so this is a `ReplyTimeoutError`
    raised at the drop instead of at the deadline. The client is left
    disconnected; `TTLockClient.connect` opens a new link.
    """
