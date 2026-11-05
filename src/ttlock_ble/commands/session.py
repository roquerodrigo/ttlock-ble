"""Payloads and parsers for the handshake that authorises every other command."""

from __future__ import annotations

from .encoding import decimal_time_bytes, int_to_bytes_be
from .envelope import RESPONSE_SUCCESS, parse_response_status

VENDOR = "0658d44e0c504619a09c5b91be75a3a8"


def payload_get_aes_key() -> bytes:
    """COMM_GET_AES_KEY data — vendor token, AES-encrypted with the session key."""
    return VENDOR.encode("ascii")


def payload_check_random(ps_from_lock: int, unlock_key: str | int) -> bytes:
    """COMM_CHECK_RANDOM — 4-byte BE of `(psFromLock + unlockKey) mod 2**32`."""
    sum_val = (int(ps_from_lock) + int(unlock_key)) & 0xFFFFFFFF
    return sum_val.to_bytes(4, "big")


def payload_check_user_time(
    uid: int = 0,
    start_date: str = "0001311400",
    end_date: str = "9911301400",
    lock_flag_pos: int = 0,
) -> bytes:
    """COMM_CHECK_USER_TIME — 17 bytes proving the key is valid right now.

    Wire layout matches `CommandUtil_V3.checkUserTime` in the official SDK:

        [0:5]    start date, one decimal byte per field (yyMMddHHmm)
        [5:10]   end date, same encoding
        [10:13]  lockFlagPos (low 3 bytes, big-endian)
        [13:17]  uid (4 bytes, big-endian)

    The lock compares `lockFlagPos` against the flag it keeps for the
    key: a key sent with a lower one is refused as reset (error 0x0D,
    `LOCK_KEY_FLAG_INVALID`), so callers pass the key's own value. The
    default dates are the "permanent key" window the official client
    falls back to when the key carries no validity period.
    """
    out = bytearray(17)
    out[0:5] = decimal_time_bytes(start_date)
    out[5:10] = decimal_time_bytes(end_date)
    out[10] = (lock_flag_pos >> 16) & 0xFF
    out[11] = (lock_flag_pos >> 8) & 0xFF
    out[12] = lock_flag_pos & 0xFF
    out[13:17] = int_to_bytes_be(uid, 4)
    return bytes(out)


def payload_check_admin(uid: int, admin_ps: str, lock_flag_pos: int) -> bytes:
    """COMM_CHECK_ADMIN — 11 bytes proving we know the admin password.

    Wire layout:

        [0:4]   admin password (4-byte BE int)
        [4:7]   lockFlagPos (3 bytes, big-endian)
        [7:11]  uid (4-byte BE int)
    """
    out = bytearray(11)
    out[0:4] = int_to_bytes_be(int(admin_ps), 4)
    out[4] = (lock_flag_pos >> 16) & 0xFF
    out[5] = (lock_flag_pos >> 8) & 0xFF
    out[6] = lock_flag_pos & 0xFF
    out[7:11] = int_to_bytes_be(uid, 4)
    return bytes(out)


def parse_check_user_time_response(plaintext: bytes) -> int:
    """Extract `psFromLock` (UInt32 BE) from the CHECK_USER_TIME response.

    Wire layout: `[cmd_echo=0x55][status=0x01][psFromLock 4 BE][...]`.
    Raises if status != SUCCESS so callers can't accidentally proceed
    with a garbage value.
    """
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS:
        raise RuntimeError(f"checkUserTime FAILED: status={status:#x} err={data.hex()}")
    if len(data) < 4:
        raise ValueError(f"checkUserTime payload too short: {plaintext.hex()}")
    return int.from_bytes(data[:4], "big")


def parse_check_admin_response(plaintext: bytes) -> int:
    """Extract the lock-issued random token from the CHECK_ADMIN response.

    Wire layout: `[cmd_echo=0x41][status][token 4 BE][...]`. Raises if
    status != SUCCESS, mirroring `parse_check_user_time_response`.
    """
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS:
        raise RuntimeError(f"checkAdmin FAILED: status={status:#x} err={data.hex()}")
    if len(data) < 4:
        raise ValueError(f"checkAdmin payload too short: {plaintext.hex()}")
    return int.from_bytes(data[:4], "big")
