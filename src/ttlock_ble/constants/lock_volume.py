"""LockVolume: keypad/lock beep volume levels for `TTLockClient.set_lock_volume`."""

from __future__ import annotations

from enum import IntEnum


class LockVolume(IntEnum):
    """Keypad/lock beep volume, named after the official app's own UI labels.

    Confirmed via 5 independently-verified real-hardware writes that the
    wire-level values are these five, in this order - see
    `commands.lock_sound.payload_set_lock_volume`. Unlike sibling enums
    in this package, the names are the official app's own UI labels, not
    independently confirmed against decompiled SDK source - this command
    was reverse-engineered from BLE traffic, not from an SDK dump.
    """

    LOW = 1
    MEDIUM_LOW = 2
    MEDIUM = 3
    MEDIUM_HIGH = 4
    HIGH = 5
