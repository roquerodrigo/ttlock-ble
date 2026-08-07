"""Bolt control and the unauthenticated state query that reports back on it."""

from __future__ import annotations

import datetime as dt

from ..constants import LockState
from .encoding import int_to_bytes_be
from .envelope import RESPONSE_SUCCESS, parse_response_status

# `cmd.LOCKED` / `cmd.UNLOCKED` are kept as aliases of the LockState enum
# members (existing callers can still write `cmd.LOCKED` and compare with
# either an int or an enum).
LOCKED = LockState.LOCKED
UNLOCKED = LockState.UNLOCKED


def payload_unlock(ps_from_lock: int, unlock_key: str | int, ts_ms: int = 0) -> bytes:
    """COMM_UNLOCK / COMM_FUNCTION_LOCK — 8-byte authenticated control payload.

    Wire layout:

        [0:4]  (psFromLock + unlockKey) as UInt32 BE  (overflow wraps mod 2**32)
        [4:8]  current unix epoch seconds, BE

    `psFromLock` is a 4-byte token returned in the CHECK_USER_TIME response.
    Adding it to our numeric `unlockKey` proves both that the time-window
    check just passed AND that we know the per-key secret.
    """
    if ts_ms <= 0:
        ts_ms = int(dt.datetime.now(dt.UTC).timestamp() * 1000)
    sum_val = (int(ps_from_lock) + int(unlock_key)) & 0xFFFFFFFF
    out = bytearray(8)
    out[0:4] = sum_val.to_bytes(4, "big")
    out[4:8] = int_to_bytes_be(ts_ms // 1000, 4)
    return bytes(out)


def payload_query_state() -> bytes:
    """COMM_SEARCH_BICYCLE_STATUS — fixed `SCIENER` ASCII literal (7 bytes)."""
    return b"SCIENER"


def parse_lock_status(plaintext: bytes) -> LockState | None:
    """Decode COMM_SEARCH_BICYCLE_STATUS lockState byte.

    Wire layout: `[cmd_echo][status][battery][lockState][...]`.
    Returns the matching `LockState` member, or `None` when the lock
    failed the request or sent a byte the firmware doesn't define.
    """
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS or len(data) < 2:
        return None
    try:
        return LockState(data[1])
    except ValueError:
        return None


def parse_state_battery(plaintext: bytes) -> int | None:
    """Battery percentage from a COMM_SEARCH_BICYCLE_STATUS response (byte 0)."""
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS or len(data) < 1:
        return None
    return data[0]
