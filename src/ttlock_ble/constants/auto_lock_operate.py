"""AutoLockOperate: sub-operation byte for COMM_AUTO_LOCK_MANAGE."""

from __future__ import annotations

from enum import IntEnum


class AutoLockOperate(IntEnum):
    """`COMM_AUTO_LOCK_MANAGE` request operation type."""

    SEARCH = 0x01
    MODIFY = 0x02
