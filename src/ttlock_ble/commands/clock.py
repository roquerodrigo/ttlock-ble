"""Reading and correcting the lock's on-board RTC."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .encoding import decimal_time_bytes, decode_date6
from .envelope import RESPONSE_SUCCESS, parse_response_status

if TYPE_CHECKING:
    import datetime as dt


def payload_time_calibrate(local_time: dt.datetime) -> bytes:
    """COMM_TIME_CALIBRATE — 6 bytes `[YY, MM, DD, HH, mm, ss]` decimal-encoded.

    Each byte is the literal decimal value (year 2026 → byte 26 = 0x1A),
    NOT BCD. The lock keeps an RTC that drifts and needs periodic
    recalibration; HA integrations typically call this on connect and
    once a day thereafter.

    `local_time` is the wall clock the lock will store and report back,
    with no offset attached — see `TTLockClient.calibrate_time` for why
    it has to be the lock's local time rather than UTC. Only the
    wall-clock fields are read, so an aware datetime is encoded as the
    time it displays.
    """
    return decimal_time_bytes(local_time.strftime("%y%m%d%H%M%S"))


def payload_get_lock_time() -> bytes:
    """COMM_GET_LOCK_TIME — empty request body; the lock replies with its RTC."""
    return b""


def parse_get_lock_time_response(plaintext: bytes) -> dt.datetime:
    """Decode the lock's current RTC into a naive `datetime` (lock-local).

    Wire layout: `[cmd_echo=0x34][status=0x01][YY][MM][DD][HH][mm][ss]`.
    Date bytes are decimal-encoded (year 2026 → byte 26 = 0x1A), matching
    `payload_time_calibrate`. Result is naive — the lock has no timezone
    (see `TTLockClient.calibrate_time`). Raises if the lock returned a
    non-SUCCESS status or a payload that doesn't decode to a valid date.
    """
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS:
        raise RuntimeError(f"getLockTime FAILED: status={status:#x} err={data.hex()}")
    parsed = decode_date6(data[:6])
    if parsed is None:
        raise ValueError(f"getLockTime payload not a valid date: {plaintext.hex()}")
    return parsed
