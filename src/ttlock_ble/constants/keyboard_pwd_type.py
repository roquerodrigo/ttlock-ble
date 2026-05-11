"""KeyboardPwdType: validity model for a keypad passcode."""

from __future__ import annotations

from enum import IntEnum


class KeyboardPwdType(IntEnum):
    """Validity model for a keyboard passcode (mirrors `KeyboardPwdType.java`)."""

    PERMANENT = 1
    COUNT = 2
    PERIOD = 3
    CIRCLE = 4
