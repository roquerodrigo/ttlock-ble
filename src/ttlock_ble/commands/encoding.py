"""Byte-level packing and unpacking shared by the V3 payload builders and parsers."""

from __future__ import annotations

import datetime as dt


def int_to_bytes_be(value: int, length: int = 4) -> bytes:
    """Pack an unsigned integer into `length` big-endian bytes."""
    return value.to_bytes(length, "big", signed=False)


def bcd_time10(time_str: str) -> bytes:
    """Pack a 10-digit `yyMMddHHmm` string into 5 BCD bytes (two digits per byte)."""
    if len(time_str) % 2:
        time_str = "0" + time_str
    out = bytearray()
    for i in range(0, len(time_str), 2):
        hi = int(time_str[i])
        lo = int(time_str[i + 1])
        out.append(((hi << 4) | lo) & 0xFF)
    return bytes(out)


def decimal_time_bytes(time_str: str) -> bytes:
    """Pack a digit string into one byte per pair, decimal-encoded.

    Mirrors `dateTimeToBuffer` in ttlock-sdk-js: `parseInt(substr(2))` per
    pair, so "26" becomes byte 26 (0x1A), NOT 0x26 like BCD would. Used by
    COMM_TIME_CALIBRATE where the lock parses the bytes into a real
    `Calendar` (so 0x1A → year 2026, 0x26 → year 2038).
    """
    if len(time_str) % 2:
        time_str = "0" + time_str
    return bytes(int(time_str[i : i + 2]) for i in range(0, len(time_str), 2))


def decode_date5(raw: bytes) -> dt.datetime | None:
    """Decode 5 decimal-encoded bytes `(yy,mm,dd,hh,mm)` into a naive `datetime`.

    Each byte holds a decimal value (e.g. 0x1a = 26 for the year 2026).
    Returns `None` if the values don't form a valid calendar date —
    matches the defensive convention in `lock_event._decode_timestamp`.
    Lock-local time; no timezone (see `TTLockClient.calibrate_time`).
    """
    if len(raw) < 5:
        return None
    try:
        return dt.datetime(2000 + raw[0], raw[1], raw[2], raw[3], raw[4])  # noqa: DTZ001 — lock RTC is naive
    except ValueError:
        return None


def decode_date6(raw: bytes) -> dt.datetime | None:
    """Decode 6 decimal-encoded bytes `(yy,mm,dd,hh,mm,ss)` into a naive `datetime`.

    Same convention as `decode_date5` plus a seconds byte. Used by the
    operate-log record header and the 0x14 log-push notification.
    """
    if len(raw) < 6:
        return None
    try:
        return dt.datetime(  # noqa: DTZ001 — lock RTC is naive
            2000 + raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]
        )
    except ValueError:
        return None


def decode_mac6(raw: bytes) -> str:
    """Decode a 6-byte little-endian MAC into the canonical `aa:bb:cc:dd:ee:ff`."""
    return ":".join(f"{octet:02x}" for octet in reversed(raw))
