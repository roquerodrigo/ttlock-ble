"""Keypad passcode provisioning (COMM_MANAGE_KEYBOARD_PASSWORD, CMD 0x03).

Layouts follow `CommandUtil_V3.manageKeyboardPassword` in the official SDK.
On an SN534 lock (firmware 6.5.20) ADD, REMOVE_ONE, MODIFY and a weekly
RECOVERY were all exercised: REMOVE_ONE ignores the type byte, and MODIFY
changes dates without changing a passcode's type.
"""

from __future__ import annotations

import datetime as dt
from typing import TYPE_CHECKING

from ..constants import KeyboardPwdType, PwdOperateType
from ..models import Period, Permanent, SingleUse
from .encoding import decimal_time_bytes, encode_date5
from .passcode_cycle import encode_passcode_cycle

if TYPE_CHECKING:
    from ..models import Weekly

# The start the lock itself reports for every permanent and dated passcode.
_UNSET_START = dt.datetime(2000, 1, 1)  # noqa: DTZ001 -- lock RTC is naive
_MODIFY_KEEPS_TYPE = 0


def check_passcode(code: str) -> None:
    """Raise `ValueError` unless `code` is 4-9 decimal digits, without quoting it."""
    if not (4 <= len(code) <= 9) or not (code.isascii() and code.isdigit()):
        raise ValueError(f"keyboard passcode must be 4-9 digits, got {len(code)} characters")


def _length_prefixed(code: str) -> bytes:
    return bytes([len(code)]) + code.encode("ascii")


def payload_passcode_add(
    pwd_type: int,
    code: str,
    start_date: str = "0001311400",
    end_date: str = "9912311400",
) -> bytes:
    """COMM_MANAGE_KEYBOARD_PASSWORD with op=ADD (2), from `YYMMDDHHmm` strings.

    Wire layout: `[op=2][type][len(code)][code chars][start 5B][end 5B?]`.
    A permanent passcode carries only the start; every other type carries
    both dates. `payload_passcode_create` builds the same frame from a
    `Validity`.
    """
    check_passcode(code)
    out = bytearray([PwdOperateType.ADD, pwd_type])
    out.extend(_length_prefixed(code))
    out.extend(decimal_time_bytes(start_date))
    if pwd_type != KeyboardPwdType.PERMANENT:
        out.extend(decimal_time_bytes(end_date))
    return bytes(out)


def payload_passcode_create(code: str, validity: Permanent | Period | SingleUse) -> bytes:
    """ADD (2) for a permanent, period or single-use passcode."""
    check_passcode(code)
    if isinstance(validity, Permanent):
        return _add(KeyboardPwdType.PERMANENT, code, encode_date5(_UNSET_START))
    pwd_type = KeyboardPwdType.PERIOD if isinstance(validity, Period) else KeyboardPwdType.COUNT
    return _add(pwd_type, code, encode_date5(validity.start) + encode_date5(validity.end))


def _add(pwd_type: KeyboardPwdType, code: str, dates: bytes) -> bytes:
    return bytes([PwdOperateType.ADD, pwd_type]) + _length_prefixed(code) + dates


def payload_passcode_recover_weekly(code: str, weekly: Weekly) -> bytes:
    """RECOVERY (6) of a CIRCLE passcode - the only way to write a weekly one.

    Wire layout: `[op=6][type=4][len][code][len][code][2000-01-01 HH:mm 5B][cycle type 2B BE]`.
    Raises `ValueError` for a schedule the cycle type cannot express - see
    `encode_passcode_cycle`.
    """
    check_passcode(code)
    start, cycle_type = encode_passcode_cycle(weekly)
    when = encode_date5(dt.datetime.combine(_UNSET_START.date(), start))
    return (
        bytes([PwdOperateType.RECOVERY, KeyboardPwdType.CIRCLE])
        + _length_prefixed(code)
        + _length_prefixed(code)
        + when
        + cycle_type.to_bytes(2, "big")
    )


def payload_passcode_modify(
    code: str,
    *,
    new_code: str | None = None,
    validity: Period | SingleUse | None = None,
) -> bytes:
    """MODIFY (5): change a passcode's digits, its dates, or both.

    Wire layout: `[op=5][0][len][code][len(new) or 0][new][start 5B][end 5B]?`,
    the dates only when `validity` is given. The type byte stays 0, as the
    official app sends it: the lock keeps the passcode's type either way.
    """
    check_passcode(code)
    if new_code is None and validity is None:
        raise ValueError("modify needs a new code, a new validity, or both")
    out = bytearray([PwdOperateType.MODIFY, _MODIFY_KEEPS_TYPE])
    out.extend(_length_prefixed(code))
    if new_code is None:
        out.append(0)
    else:
        check_passcode(new_code)
        out.extend(_length_prefixed(new_code))
    if validity is not None:
        out.extend(encode_date5(validity.start) + encode_date5(validity.end))
    return bytes(out)


def payload_passcode_delete(pwd_type: int, code: str) -> bytes:
    """COMM_MANAGE_KEYBOARD_PASSWORD with op=REMOVE_ONE (3); the lock ignores `pwd_type`."""
    check_passcode(code)
    return bytes([PwdOperateType.REMOVE_ONE, pwd_type]) + _length_prefixed(code)


def payload_passcode_clear() -> bytes:
    """COMM_MANAGE_KEYBOARD_PASSWORD with op=CLEAR (1) — wipes all keypad codes."""
    return bytes([PwdOperateType.CLEAR])
