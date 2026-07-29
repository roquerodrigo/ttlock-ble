"""LockAdvertisement: lock state decoded from a BLE advertisement, without connecting."""

from __future__ import annotations

from dataclasses import dataclass

from ..constants import LockState
from .lock_version import LockVersion

_MIN_MANUFACTURER_LENGTH = 15
_MAC_LENGTH = 6
_V3_HEADER = (5, 3)
_DFU_HEADERS = frozenset({(18, 25), (0xFF, 0xFF)})
_MIN_STATEFUL_PROTOCOL_TYPE = 5
_LOCK_TYPE_V2S = 3
_UNLOCKED_BIT = 0x01
_NEW_RECORDS_BIT = 0x02
_SETTING_MODE_BIT = 0x04


@dataclass(frozen=True, slots=True)
class LockAdvertisement:
    """Bolt state, pending-records flag and battery, read straight off an advertisement.

    The firmware folds these into the manufacturer data of every
    advertisement, so a passive listener tracks the lock without ever
    opening a BLE session. That is the only way to observe an auto-lock:
    the firmware writes no operation-log record for it, and a lock that
    already dropped the session has no channel left to push an event on.

    Field layout mirrors `TTBluetoothDevice.parseManufacturerData` from
    the decompiled vendor SDK. Locks older than protocol type 5 (and the
    V2S family) stop the layout before the flags byte and carry no state
    at all — `from_manufacturer_data` returns `None` for those.
    """

    protocol_type: int
    protocol_version: int
    scene: int
    lock_state: LockState
    has_new_records: bool
    is_setting_mode: bool
    battery: int
    lock_mac: str

    @classmethod
    def from_manufacturer_data(
        cls,
        company_id: int,
        payload: bytes,
    ) -> LockAdvertisement | None:
        """Decode one manufacturer-data entry, or `None` when it carries no state.

        `company_id` and `payload` are the key and value of a single entry
        of bleak's `AdvertisementData.manufacturer_data`. Bleak splits the
        two-byte company identifier off the AD structure, but the lock
        reuses those bytes as its first protocol fields, so they are
        joined back on before decoding.

        Returns `None` — never raises — for anything that is not a
        stateful TTLock advertisement: a short payload, firmware-update
        mode, or a lock family whose layout has no flags byte. Callers
        should compare `lock_mac` against the address they expected
        before trusting the decoded state.
        """
        raw = company_id.to_bytes(2, "little") + bytes(payload)
        if len(raw) < _MIN_MANUFACTURER_LENGTH:
            return None
        header = (raw[0], raw[1])
        if header in _DFU_HEADERS:
            return None
        if header == _V3_HEADER:
            protocol_type, protocol_version = header
            scene = raw[2]
            flags_offset = 3
        else:
            protocol_type, protocol_version = raw[4], raw[5]
            scene = raw[7]
            flags_offset = 8
        version = LockVersion(
            protocolType=protocol_type,
            protocolVersion=protocol_version,
            scene=scene,
            groupId=0,
            orgId=0,
        )
        if protocol_type < _MIN_STATEFUL_PROTOCOL_TYPE or version.lock_type() == _LOCK_TYPE_V2S:
            return None
        flags = raw[flags_offset]
        return cls(
            protocol_type=protocol_type,
            protocol_version=protocol_version,
            scene=scene,
            lock_state=LockState.UNLOCKED if flags & _UNLOCKED_BIT else LockState.LOCKED,
            has_new_records=bool(flags & _NEW_RECORDS_BIT),
            is_setting_mode=bool(flags & _SETTING_MODE_BIT),
            battery=raw[flags_offset + 1],
            lock_mac=_decode_mac(raw[-_MAC_LENGTH:]),
        )


def _decode_mac(tail: bytes) -> str:
    """Format the advertisement's trailing six bytes as a colon-separated MAC.

    The firmware appends the address in reverse byte order; the vendor
    SDK's documented offset for it does not survive contact with real
    scans, so the last six bytes are taken instead.
    """
    return ":".join(f"{byte:02X}" for byte in reversed(tail))
