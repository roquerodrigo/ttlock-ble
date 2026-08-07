"""Decoding of a single operate-log record body into a `LogEntry`."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..constants import LogOperate
from ..models import LogEntry
from .encoding import decode_date5, decode_mac6

if TYPE_CHECKING:
    import datetime as dt
    from collections.abc import Callable


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


@dataclass(frozen=True, slots=True)
class _RecordTail:
    """The fields a record body contributes on top of the fixed header.

    Every field defaults to `None` so a decoder only names what its record
    type actually carries, and a body too short to hold its tail degrades to
    an empty tail instead of raising — the same tolerance the Android SDK's
    length guards give.
    """

    uid: int | None = None
    record_id: int | None = None
    password: str | None = None
    new_password: str | None = None
    delete_date: dt.datetime | None = None
    key_id: int | None = None
    accessory_battery: int | None = None
    start_date: dt.datetime | None = None
    end_date: dt.datetime | None = None


type _TailDecoder = Callable[[bytes], _RecordTail]


def _decode_app_uid_record_id(payload: bytes) -> _RecordTail:
    """App / BLE / gateway record: 4-byte user id followed by 4-byte record id."""
    if len(payload) < 8:
        return _RecordTail()
    return _RecordTail(
        uid=int.from_bytes(payload[:4], "big"),
        record_id=int.from_bytes(payload[4:8], "big"),
    )


def _decode_remote_control_key(payload: bytes) -> _RecordTail:
    """REMOTE_CONTROL_KEY: the app tail plus the accessory's key id."""
    if len(payload) < 9:
        return _RecordTail()
    return _RecordTail(
        uid=int.from_bytes(payload[:4], "big"),
        record_id=int.from_bytes(payload[4:8], "big"),
        key_id=payload[8],
    )


def _decode_passcode_pair(payload: bytes) -> _RecordTail:
    """Keypad records carrying a passcode and, for the modify variants, its replacement."""
    password, new_password, _ = _decode_pwd_pair(payload)
    return _RecordTail(password=password, new_password=new_password)


def _decode_passcode_only(payload: bytes) -> _RecordTail:
    """ERROR_PWD: the rejected passcode, with any trailing bytes ignored."""
    password, _, _ = _decode_pwd_pair(payload)
    return _RecordTail(password=password)


def _decode_clear_all_passcodes(payload: bytes) -> _RecordTail:
    """Record for a bulk passcode wipe: the deletion date, optionally with a passcode."""
    if len(payload) < 5:
        return _RecordTail()
    password: str | None = None
    if len(payload) > 5:
        password, _, _ = _decode_pwd_pair(payload[5:])
    return _RecordTail(delete_date=decode_date5(payload[:5]), password=password)


def _decode_card_number(payload: bytes) -> _RecordTail:
    """IC-card record: a variable-length card number read as a big-endian unsigned int.

    The SDK consumes whatever is left of the body — 4 bytes on older firmware,
    8 on newer — rather than a fixed width.
    """
    if not payload:
        return _RecordTail()
    return _RecordTail(password=str(int.from_bytes(payload, "big")))


def _decode_six_byte_id(payload: bytes) -> _RecordTail:
    """Fingerprint, palm-vein and QR records: a 6-byte biometric or credential id."""
    if len(payload) < 6:
        return _RecordTail()
    return _RecordTail(password=str(int.from_bytes(payload[:6], "big")))


def _decode_short_id(payload: bytes) -> _RecordTail:
    """Decode a credential id encoded as a 2-byte value."""
    if len(payload) < 2:
        return _RecordTail()
    return _RecordTail(password=str(int.from_bytes(payload[:2], "big")))


def _decode_accessory_battery(payload: bytes) -> _RecordTail:
    """Door-sensor records: the sensor's own battery level, not the lock's."""
    if not payload:
        return _RecordTail()
    return _RecordTail(accessory_battery=payload[0])


def _decode_mac_only(payload: bytes) -> _RecordTail:
    """BONG_UNLOCK and third-device records: the peer's MAC address and nothing else."""
    if len(payload) < 6:
        return _RecordTail()
    return _RecordTail(password=decode_mac6(payload[:6]))


def _decode_key_fob(payload: bytes) -> _RecordTail:
    """WIRELESS_KEY_FOB and the double-check fob: MAC, then optional key id and battery."""
    if len(payload) < 6:
        return _RecordTail()
    return _RecordTail(
        password=decode_mac6(payload[:6]),
        key_id=payload[6] if len(payload) >= 7 else None,
        accessory_battery=payload[7] if len(payload) >= 8 else None,
    )


def _decode_wireless_keypad(payload: bytes) -> _RecordTail:
    """WIRELESS_KEY_PAD: MAC then battery, with no key id in between."""
    if len(payload) < 6:
        return _RecordTail()
    return _RecordTail(
        password=decode_mac6(payload[:6]),
        accessory_battery=payload[6] if len(payload) >= 7 else None,
    )


def _decode_added_passcode(payload: bytes) -> _RecordTail:
    """ADD_PASSCODE_SUCCESSFULLY: the passcode followed by its 5-byte validity window."""
    if not payload:
        return _RecordTail()
    pwd_len = payload[0]
    if 1 + pwd_len > len(payload):
        return _RecordTail()
    tail = payload[1 + pwd_len :]
    return _RecordTail(
        password=payload[1 : 1 + pwd_len].decode("ascii", errors="replace"),
        start_date=decode_date5(tail[:5]) if len(tail) >= 5 else None,
        end_date=decode_date5(tail[5:10]) if len(tail) >= 10 else None,
    )


# Record-type buckets from the switch in `CommandUtil_V3.parseOperateLog`
# (TTLock Android SDK). Keeping these as bare ints (rather than
# `LogOperate.X.value`) keeps the cross-reference to the Java cases legible;
# the buckets are disjoint, which is what lets the switch become a lookup.
_TAIL_DECODERS_BY_BUCKET: tuple[tuple[frozenset[int], _TailDecoder], ...] = (
    (frozenset({1, 26, 28, 41, 52, 75, 76, 77}), _decode_app_uid_record_id),
    (frozenset({37}), _decode_remote_control_key),
    (frozenset({4, 5, 6, 9, 10, 11, 12, 13, 34, 38, 78, 92}), _decode_passcode_pair),
    (frozenset({7}), _decode_passcode_only),
    (frozenset({8}), _decode_clear_all_passcodes),
    (frozenset({15, 17, 18, 25, 35, 39, 51, 74, 80, 91}), _decode_card_number),
    (frozenset({20, 21, 22, 23, 33, 40, 79}), _decode_six_byte_id),
    (frozenset({30, 31}), _decode_accessory_battery),
    (frozenset({19}), _decode_mac_only),
    (frozenset({55, 82}), _decode_key_fob),
    (frozenset({56}), _decode_wireless_keypad),
    (frozenset({57, 58}), _decode_short_id),
    (frozenset({67, 68, 69, 70, 71, 72, 81, 83, 84, 85, 86, 87, 88, 89}), _decode_six_byte_id),
    (frozenset({93}), _decode_added_passcode),
    (frozenset({94, 95, 96, 97, 98, 99, 100}), _decode_mac_only),
)

_TAIL_DECODERS: dict[int, _TailDecoder] = {
    record_type: decoder
    for record_types, decoder in _TAIL_DECODERS_BY_BUCKET
    for record_type in record_types
}


def decode_log_record(  # noqa: PLR0913, PLR0917 -- header fields arrive individually from the pager
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
    (TTLock Android SDK): each decoder interprets the variable-length tail
    that follows the fixed header (`record_type` + 6-byte date + battery).
    Record types with no tail of their own contribute nothing beyond it.
    """
    decoder = _TAIL_DECODERS.get(record_type)
    tail = decoder(data[idx:rec_end]) if decoder is not None else _RecordTail()

    return LogEntry(
        record_number=sequence,
        record_type=LogOperate.coerce(record_type),
        operate_date=operate_date,
        lock_battery=battery,
        uid=tail.uid,
        record_id=tail.record_id,
        password=tail.password,
        new_password=tail.new_password,
        delete_date=tail.delete_date,
        key_id=tail.key_id,
        accessory_battery=tail.accessory_battery,
        start_date=tail.start_date,
        end_date=tail.end_date,
    )
