"""Keypad passcode provisioning (COMM_MANAGE_KEYBOARD_PASSWORD)."""

from __future__ import annotations

from ..constants import KeyboardPwdType, PwdOperateType
from .encoding import decimal_time_bytes


def _check_passcode(code: str) -> None:
    if not (4 <= len(code) <= 9) or not code.isdigit():
        raise ValueError(f"keyboard passcode must be 4-9 digits, got {code!r}")


def payload_passcode_add(
    pwd_type: int,
    code: str,
    start_date: str = "0001311400",
    end_date: str = "9912311400",
) -> bytes:
    """COMM_MANAGE_KEYBOARD_PASSWORD with op=ADD (2).

    Wire layout: `[op=2][type][len(code)][code chars][start 5B][end 5B?]`.
    Permanent passcodes carry both 5-byte windows; non-permanent ones omit
    the trailing end-date block (mirrors `ManageKeyboardPasswordCommand.buildAdd`).
    """
    _check_passcode(code)
    out = bytearray()
    out.append(PwdOperateType.ADD)
    out.append(pwd_type)
    out.append(len(code))
    out.extend(code.encode("ascii"))
    out.extend(decimal_time_bytes(start_date))
    if pwd_type != KeyboardPwdType.PERMANENT:
        out.extend(decimal_time_bytes(end_date))
    return bytes(out)


def payload_passcode_delete(pwd_type: int, code: str) -> bytes:
    """COMM_MANAGE_KEYBOARD_PASSWORD with op=REMOVE_ONE (3)."""
    _check_passcode(code)
    out = bytearray()
    out.append(PwdOperateType.REMOVE_ONE)
    out.append(pwd_type)
    out.append(len(code))
    out.extend(code.encode("ascii"))
    return bytes(out)


def payload_passcode_clear() -> bytes:
    """COMM_MANAGE_KEYBOARD_PASSWORD with op=CLEAR (1) — wipes all keypad codes."""
    return bytes([PwdOperateType.CLEAR])
