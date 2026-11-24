"""The keypad admin passcode - read with CMD 0x65, written with CMD 0x53.

Layouts follow the official SDK (`getAdminCode`, `setAdminKeyboardPwd`);
the read is confirmed on hardware. The value unlocks the door and opens
the lock's settings menu, so nothing here logs or echoes it.
"""

from __future__ import annotations

from .passcode import check_passcode


def payload_set_admin_passcode(code: str) -> bytes:
    """CMD 0x53: one byte per digit, holding the digit's value rather than its ASCII code."""
    check_passcode(code)
    return bytes(int(digit) for digit in code)


def parse_admin_passcode(data: bytes) -> str:
    """Decode the data of a successful CMD 0x65 reply: `[battery][length][ASCII digits]`.

    Raises `ValueError` when the length byte and the digits disagree, or
    the digits are not decimal - without quoting them.
    """
    if len(data) < 2 or len(data) - 2 != data[1]:
        raise ValueError(f"admin passcode reply has an unexpected length ({len(data)} bytes)")
    digits = data[2:]
    if not digits.isdigit():
        raise ValueError("admin passcode reply carries non-digit characters")
    return digits.decode("ascii")
