"""Reading back keypad passcodes - CMD 0x07, a sequence-cursor query.

Reverse-engineered from device traffic. See `TTLockClient.get_passcodes`
for the critical scope limitation - confirmed via extensive live testing,
this query does NOT surface every passcode active on the lock.

Wire layout of one SUCCESS response's data:

    [0:4]   header - `header[2:4]` is `next_sequence` (big-endian), fed
            back as the next request's sequence number; `header[0:2]`'s
            meaning is unconfirmed.
    [4]     item_len - read but not used: every field after it is already
            self-length-prefixed, so nothing here depends on its value.
    [5]     pwd_type (`KeyboardPwdType`)
    [6]     new_pwd_len
    [7:...] new_pwd (ASCII digits)
    [...]   pwd_len
    [...]   pwd (ASCII digits)
    [...]   trailer - length and structure depend on `pwd_type`, see
            `_TRAILER_LEN` and `parse_passcode_list_response`.

End of list: confirmed on real hardware as a bare 2-byte `0000` response -
too short to even carry a full 4-byte header, let alone an item. A
response carrying a real entry can also set `next_sequence == 0` in the
same reply - that entry is still valid, just the last one to fetch.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..constants import KeyboardPwdType
from ..models import CyclicSchedule, PasscodeEntry
from .encoding import decode_date5
from .envelope import RESPONSE_SUCCESS, parse_response_status

if TYPE_CHECKING:
    import datetime as dt

_HEADER_LEN = 4
_MIN_ITEM_LEN = 4  # item_len + pwd_type + new_pwd_len + pwd_len, before either code's digits

_TRAILER_LEN = {
    KeyboardPwdType.PERMANENT: 5,  # [start_date: 5], always the sentinel in every example seen
    KeyboardPwdType.PERIOD: 10,  # [start_date: 5][end_date: 5]
    KeyboardPwdType.CIRCLE: 7,  # [date sentinel: 3][start_hour][start_minute][?][low_byte]
}

# Confirmed BASE_SELECTOR values (see `CyclicSchedule` for what's actually
# verified on real hardware versus formula-predicted). Individual days
# follow `(iso_weekday + 1) * 24`, Monday=1..Sunday=7; Daily/Workdays share
# that formula with index 0/1; Weekend is a fixed, non-formula constant.
#
# There is no separate wire byte for this value - real captures disproved
# that assumption (trailer[5] does not hold it; see
# `parse_passcode_list_response`'s docstring). BASE_SELECTOR only exists
# as a derived quantity: the largest one of these <= the wire's low_byte,
# with the remainder being `duration_hours - 1`.
_CYCLIC_BASE_SELECTORS = {
    0: "Daily",
    24: "Workdays",
    48: "Monday",
    72: "Tuesday",
    96: "Wednesday",  # formula-predicted, not independently confirmed on real hardware
    120: "Thursday",  # formula-predicted, not independently confirmed on real hardware
    144: "Friday",  # formula-predicted, not independently confirmed on real hardware
    168: "Saturday",
    192: "Sunday",
    232: "Weekend",
}
_CYCLIC_BASES_DESCENDING = sorted(_CYCLIC_BASE_SELECTORS, reverse=True)


def payload_passcode_list(sequence: int) -> bytes:
    """Build the CMD 0x07 payload for one page: `sequence` as UInt16 BE.

    Start at `sequence=0`; pass back whatever `next_sequence`
    `parse_passcode_list_response` returned to fetch the next page, until
    it returns 0.
    """
    return sequence.to_bytes(2, "big")


def _decode_date_or_raise(raw: bytes, label: str, plaintext: bytes) -> dt.datetime:
    parsed = decode_date5(raw)
    if parsed is None:
        raise ValueError(f"passcode list {label} not a valid date: {plaintext.hex()}")
    return parsed


def _decode_cyclic_schedule(trailer: bytes) -> CyclicSchedule:
    """Decode a CIRCLE trailer: `[0:3]` a discarded date sentinel, `[3:5]` start_hour/minute.

    `trailer[5]`'s meaning is unconfirmed - real captures show it as 3
    for every Weekend-preset entry and 4 for every other one seen, but
    that is too thin a pattern to name or rely on, so it is deliberately
    left undecoded here.

    `trailer[6]` (`low_byte`) is the *only* place BASE_SELECTOR and
    duration are encoded - see `_CYCLIC_BASE_SELECTORS`. The originally
    assumed separate `base_selector` wire byte does not exist; this was
    corrected against real hardware captures that a literal per-field
    reading of `low_byte` alone could not otherwise explain.
    """
    low_byte = trailer[6]
    base_selector = next(base for base in _CYCLIC_BASES_DESCENDING if base <= low_byte)
    return CyclicSchedule(
        day_or_preset=_CYCLIC_BASE_SELECTORS[base_selector],
        start_hour=trailer[3],
        start_minute=trailer[4],
        duration_hours=low_byte - base_selector + 1,
    )


def parse_passcode_list_response(plaintext: bytes) -> tuple[PasscodeEntry | None, int]:
    """Decode one CMD 0x07 response into `(entry, next_sequence)`.

    `entry` is `None` at the end of the list - confirmed on real hardware
    as a bare 2-byte `0000` response, too short to even carry a full
    4-byte header; `next_sequence` is then reported as 0 since none was
    present to read. A response too short to hold an item but long
    enough for a header is treated the same way, using whatever
    `next_sequence` it did carry - real captures never showed this
    combination, so it is a defensive fallback, not a confirmed shape.
    Otherwise `entry` is the decoded passcode, and `next_sequence` (0 at
    the end of the list) is what to pass to `payload_passcode_list` for
    the next page; a caller should stop after this call once
    `next_sequence == 0`, even if it returned alongside a real final
    entry.

    Raises `RuntimeError` on a FAILED status. Raises `ValueError` if the
    item its own length-prefixed fields describe runs past the end of
    the payload, has an unrecognized `pwd_type`, or a `pwd_type` with no
    confirmed trailer layout.
    """
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS:
        raise RuntimeError(f"passcode list FAILED: status={status:#x} err={data.hex()}")
    if len(data) < _HEADER_LEN:
        return None, 0
    next_sequence = int.from_bytes(data[2:4], "big")
    rest = data[_HEADER_LEN:]
    if len(rest) < _MIN_ITEM_LEN:
        return None, next_sequence

    idx = 1  # rest[0] is item_len - see the module docstring
    pwd_type_raw = rest[idx]
    idx += 1
    try:
        pwd_type = KeyboardPwdType(pwd_type_raw)
    except ValueError as error:
        raise ValueError(
            f"passcode list unknown pwd_type={pwd_type_raw}: {plaintext.hex()}"
        ) from error
    new_pwd_len = rest[idx]
    idx += 1
    new_pwd = rest[idx : idx + new_pwd_len]
    idx += new_pwd_len
    pwd_len = rest[idx]
    idx += 1
    idx += pwd_len  # pwd itself is skipped - passcode exposes new_pwd, see PasscodeEntry

    trailer_len = _TRAILER_LEN.get(pwd_type)
    if trailer_len is None:
        raise ValueError(
            f"passcode list pwd_type={pwd_type.name} has no confirmed layout: {plaintext.hex()}"
        )
    trailer = rest[idx : idx + trailer_len]
    if len(trailer) < trailer_len:
        raise ValueError(f"passcode list payload too short for its trailer: {plaintext.hex()}")

    start_date: dt.datetime | None = None
    end_date: dt.datetime | None = None
    cyclic_schedule: CyclicSchedule | None = None
    if pwd_type == KeyboardPwdType.PERMANENT:
        start_date = _decode_date_or_raise(trailer[0:5], "start_date", plaintext)
    elif pwd_type == KeyboardPwdType.PERIOD:
        start_date = _decode_date_or_raise(trailer[0:5], "start_date", plaintext)
        end_date = _decode_date_or_raise(trailer[5:10], "end_date", plaintext)
    else:
        cyclic_schedule = _decode_cyclic_schedule(trailer)

    entry = PasscodeEntry(
        passcode=new_pwd.decode("ascii"),
        pwd_type=pwd_type,
        start_date=start_date,
        end_date=end_date,
        cyclic_schedule=cyclic_schedule,
    )
    return entry, next_sequence
