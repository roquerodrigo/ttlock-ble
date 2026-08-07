"""Reading and correcting the lock's on-board RTC."""

from __future__ import annotations

import datetime as dt

from .encoding import decimal_time_bytes, decode_date6
from .envelope import RESPONSE_SUCCESS, parse_response_status


def payload_time_calibrate(when: dt.datetime | None = None) -> bytes:
    """COMM_TIME_CALIBRATE — 6 bytes `[YY, MM, DD, HH, mm, ss]` decimal-encoded.

    Each byte is the literal decimal value (year 2026 → byte 26 = 0x1A),
    NOT BCD. The lock keeps an RTC that drifts and needs periodic
    recalibration; HA integrations typically call this on connect and
    once a day thereafter.
    """
    moment = when or dt.datetime.now(dt.UTC)
    return decimal_time_bytes(moment.strftime("%y%m%d%H%M%S"))


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
