"""The auto-lock delay: querying it, changing it, reading the answer back."""

from __future__ import annotations

from ..constants import AutoLockOperate
from .envelope import RESPONSE_SUCCESS, parse_response_status


def payload_auto_lock_search() -> bytes:
    """Query the lock's current auto-lock delay (single op-type byte = SEARCH=0x01)."""
    return bytes([AutoLockOperate.SEARCH])


def payload_auto_lock_set(seconds: int) -> bytes:
    """Set the auto-lock delay to `seconds` (3 bytes: op-type + UInt16 BE).

    `seconds=0` disables auto-lock; otherwise must fit in a UInt16 (max ~18h).
    """
    if not 0 <= seconds <= 0xFFFF:
        raise ValueError(f"auto-lock seconds out of range [0, 65535]: {seconds}")
    return bytes([AutoLockOperate.MODIFY, (seconds >> 8) & 0xFF, seconds & 0xFF])


def parse_auto_lock_response(plaintext: bytes) -> tuple[int, int | None]:
    """Decode a COMM_AUTO_LOCK_MANAGE response.

    Returns `(seconds, battery_pct)`. `seconds=-1` means UNKNOWN, reached
    only for a non-SEARCH op-type echo (e.g. a MODIFY ack, which by
    design carries no seconds field - not a failure). A SEARCH echo
    (op_type=1) that's missing its own seconds bytes is a different,
    genuinely anomalous case and raises `ValueError` rather than
    collapsing into the same -1 sentinel - a truncated response is not
    "no value by design". Raises `RuntimeError` if status != SUCCESS,
    matching `parse_check_user_time_response` - a FAILED status must not
    collapse into UNKNOWN either, or a genuine rejection goes silently
    unnoticed by the caller.

    Wire layout (after the universal envelope):

        [0]    battery percentage
        [1]    op type echo (1=SEARCH, 2=MODIFY)
        [2:4]  current value (only on SEARCH)
        [4:6]  min allowed (optional)
        [6:8]  max allowed (optional)
    """
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS:
        raise RuntimeError(f"autoLockManage FAILED: status={status:#x} err={data.hex()}")
    if len(data) < 2:
        raise ValueError(f"autoLockManage payload too short: {plaintext.hex()}")
    battery = data[0]
    op_type = data[1]
    if op_type != 1:
        return -1, battery
    if len(data) < 4:
        raise ValueError(f"autoLockManage SEARCH payload missing seconds: {plaintext.hex()}")
    return int.from_bytes(data[2:4], "big"), battery
