"""PwdOperateType: sub-operation byte for COMM_MANAGE_KEYBOARD_PASSWORD."""

from __future__ import annotations

from enum import IntEnum


class PwdOperateType(IntEnum):
    """Sub-operation for `COMM_MANAGE_KEYBOARD_PASSWORD`."""

    CLEAR = 1
    ADD = 2
    REMOVE_ONE = 3
    MODIFY = 5
    RECOVERY = 6
