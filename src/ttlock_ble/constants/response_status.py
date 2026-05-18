"""ResponseStatus: the universal status byte in a lock response/event frame."""

from __future__ import annotations

from enum import IntEnum


class ResponseStatus(IntEnum):
    """Status byte in the `[cmd_echo][status][data...]` response wrapper.

    `SUCCESS` means the command completed; `FAILED` means the lock
    rejected it and the error code is in `data[0]`.
    """

    FAILED = 0x00
    SUCCESS = 0x01
