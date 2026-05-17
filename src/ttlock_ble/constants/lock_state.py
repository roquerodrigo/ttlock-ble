"""LockState: the two values the firmware reports for the bolt position."""

from __future__ import annotations

from enum import IntEnum


class LockState(IntEnum):
    """Bolt state byte from COMM_SEARCH_BICYCLE_STATUS / the 0x14 push event."""

    LOCKED = 0
    UNLOCKED = 1
