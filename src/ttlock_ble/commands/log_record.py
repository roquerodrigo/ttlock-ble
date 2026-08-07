"""Decoding of a single operate-log record body into a `LogEntry`."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..constants import LogOperate
from ..models import LogEntry
from .encoding import decode_date5, decode_mac6

if TYPE_CHECKING:
    import datetime as dt


def _decode_pwd_pair(payload: bytes) -> tuple[str | None, str | None, int]:
    """Decode `(pwd_len, pwd, new_pwd_len, new_pwd)` — returns (pwd, new_pwd, consumed)."""
    if not payload:
        return None, None, 0
    pwd_len = payload[0]
    if 1 + pwd_len > len(payload):
        return None, None, 0
    pwd = payload[1 : 1 + pwd_len].decode("ascii", errors="replace")
    consumed = 1 + pwd_len
    if consumed >= len(payload):
        return pwd, None, consumed
    new_len = payload[consumed]
    consumed += 1
    new_pwd = payload[consumed : consumed + new_len].decode("ascii", errors="replace")
    return pwd, new_pwd, consumed + new_len


# Record-type buckets from `CommandUtil_V3.parseOperateLog` in the TTLock
# Android SDK. Keeping these as bare ints (rather than `LogOperate.X.value`)
# keeps the cross-reference to the Java switch statement legible.
_APP_UID_RID = {1, 26, 28, 41, 52, 75, 76, 77}
_PWD_PAIR = {4, 5, 6, 9, 10, 11, 12, 13, 34, 38, 78, 92}
_ERROR_PWD_ONLY = {7}
_CLEAR_ALL = {8}
_CARD_LONG = {15, 17, 18, 25, 35, 39, 51, 74, 80, 91}
_FINGERPRINT_6B = {20, 21, 22, 23, 33, 40, 79}
_DOOR_SENSOR = {30, 31}
_SIX_BYTE_ID = {67, 68, 69, 70, 71, 72, 81, 83, 84, 85, 86, 87, 88, 89}
_SHORT_ID = {57, 58}
_THIRD_DEVICE_MAC = {94, 95, 96, 97, 98, 99, 100}


def decode_log_record(  # noqa: PLR0913, PLR0917, PLR0912, PLR0915  -- flat switch mirrors the SDK
    record_type: int,
    operate_date: dt.datetime | None,
    battery: int,
    sequence: int,
    data: bytes,
    idx: int,
    rec_end: int,
) -> LogEntry:
    """Build a `LogEntry` from one record body.

    Dispatch is a port of the switch in `CommandUtil_V3.parseOperateLog`
    (TTLock Android SDK). Each case interprets the variable-length tail
    that follows the fixed header (`record_type` + 6-byte date + battery).
    """
    payload = data[idx:rec_end]
    uid: int | None = None
    record_id: int | None = None
    password: str | None = None
    new_password: str | None = None
    delete_date: dt.datetime | None = None
    key_id: int | None = None
    accessory_battery: int | None = None
    start_date: dt.datetime | None = None
    end_date: dt.datetime | None = None

    if record_type in _APP_UID_RID and len(payload) >= 8:
        uid = int.from_bytes(payload[:4], "big")
        record_id = int.from_bytes(payload[4:8], "big")
    elif record_type == 37 and len(payload) >= 9:  # REMOTE_CONTROL_KEY
        uid = int.from_bytes(payload[:4], "big")
        record_id = int.from_bytes(payload[4:8], "big")
        key_id = payload[8]
    elif record_type in _PWD_PAIR:
        password, new_password, _ = _decode_pwd_pair(payload)
    elif record_type in _ERROR_PWD_ONLY:
        password, _, _ = _decode_pwd_pair(payload)
    elif record_type in _CLEAR_ALL and len(payload) >= 5:
        delete_date = decode_date5(payload[:5])
        if len(payload) > 5:
            password, _, _ = _decode_pwd_pair(payload[5:])
    elif record_type in _CARD_LONG and payload:
        # Variable-length card id; the SDK reads whatever is left as a big-
        # endian unsigned int (4 bytes on older firmware, 8 on newer).
        password = str(int.from_bytes(payload, "big"))
    elif record_type in _FINGERPRINT_6B and len(payload) >= 6:
        password = str(int.from_bytes(payload[:6], "big"))
    elif record_type in _DOOR_SENSOR and payload:
        accessory_battery = payload[0]
    elif record_type == 19 and len(payload) >= 6:  # BONG_UNLOCK — MAC only
        password = decode_mac6(payload[:6])
    elif record_type in {55, 82} and len(payload) >= 6:  # WIRELESS_KEY_FOB / double-check fob
        password = decode_mac6(payload[:6])
        if len(payload) >= 7:
            key_id = payload[6]
        if len(payload) >= 8:
            accessory_battery = payload[7]
    elif record_type == 56 and len(payload) >= 6:  # WIRELESS_KEY_PAD — MAC + battery (no key_id)
        password = decode_mac6(payload[:6])
        if len(payload) >= 7:
            accessory_battery = payload[6]
    elif record_type in _SHORT_ID and len(payload) >= 2:
        password = str(int.from_bytes(payload[:2], "big"))
    elif record_type in _SIX_BYTE_ID and len(payload) >= 6:
        password = str(int.from_bytes(payload[:6], "big"))
    elif record_type == 93 and payload:  # ADD_PASSCODE_SUCCESSFULLY: pwd + start(5) + end(5)
        pwd_len = payload[0]
        if 1 + pwd_len <= len(payload):
            password = payload[1 : 1 + pwd_len].decode("ascii", errors="replace")
            tail = payload[1 + pwd_len :]
            if len(tail) >= 5:
                start_date = decode_date5(tail[:5])
            if len(tail) >= 10:
                end_date = decode_date5(tail[5:10])
    elif record_type in _THIRD_DEVICE_MAC and len(payload) >= 6:
        password = decode_mac6(payload[:6])

    return LogEntry(
        record_number=sequence,
        record_type=LogOperate.coerce(record_type),
        operate_date=operate_date,
        lock_battery=battery,
        uid=uid,
        record_id=record_id,
        password=password,
        new_password=new_password,
        delete_date=delete_date,
        key_id=key_id,
        accessory_battery=accessory_battery,
        start_date=start_date,
        end_date=end_date,
    )
