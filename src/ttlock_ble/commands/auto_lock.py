"""The auto-lock delay: querying it, changing it, reading the answer back."""

from __future__ import annotations

from ..constants import AutoLockOperate
from ..models import AutoLockLimits
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


def _successful_data(plaintext: bytes) -> bytes:
    """Return the payload of a COMM_AUTO_LOCK_MANAGE response, or raise.

    Raises `RuntimeError` if the lock rejected the request and
    `ValueError` if the payload is too short to carry a battery byte and
    an op-type echo.
    """
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS:
        raise RuntimeError(f"autoLockManage FAILED: status={status:#x} err={data.hex()}")
    if len(data) < 2:
        raise ValueError(f"autoLockManage payload too short: {plaintext.hex()}")
    return data


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
        [4:6]  min allowed (SEARCH only - see `parse_auto_lock_limits_response`)
        [6:8]  max allowed (SEARCH only - see `parse_auto_lock_limits_response`)
    """
    data = _successful_data(plaintext)
    battery = data[0]
    op_type = data[1]
    if op_type != 1:
        return -1, battery
    if len(data) < 4:
        raise ValueError(f"autoLockManage SEARCH payload missing seconds: {plaintext.hex()}")
    return int.from_bytes(data[2:4], "big"), battery


def parse_auto_lock_limits_response(plaintext: bytes) -> AutoLockLimits:
    """Decode the min/max allowed auto-lock seconds from a SEARCH response.

    Only present on a SEARCH-type ack, same wire frame
    `parse_auto_lock_response` reads (see its `[4:6]`/`[6:8]` layout
    note) - the two concerns just happen to arrive in the same
    response. Raises `RuntimeError` on a FAILED status, and `ValueError`
    if the response isn't a SEARCH echo or is missing the min/max bytes,
    mirroring `parse_auto_lock_response`'s truncated-SEARCH handling.

    Confirmed via direct rejection testing on one physical lock (not
    just decoding the bytes) - see `AutoLockLimits` for the values and
    what "confirmed" means here.
    """
    data = _successful_data(plaintext)
    op_type = data[1]
    if op_type != 1:
        raise ValueError(f"autoLockManage limits need a SEARCH response, got op_type={op_type}")
    if len(data) < 8:
        raise ValueError(f"autoLockManage SEARCH payload missing min/max: {plaintext.hex()}")
    return AutoLockLimits(
        min_allowed=int.from_bytes(data[4:6], "big"),
        max_allowed=int.from_bytes(data[6:8], "big"),
    )
