"""ttlock_ble: Python SDK for DLock-XP / TTLock smart locks over Bluetooth.

Public API:
    TTLockClient   — async BLE client for an already-paired lock
    TTLockCloud    — async HTTP client for the TTLock cloud (key bootstrap)
    VirtualKey     — per-(user, lock) credential bundle
    LockVersion    — firmware identifiers used in the V3 frame header
    SiteInfo       — regional API endpoints (siteId, country, base URL)
    LockAdvertisement — bolt state + battery decoded from a BLE advertisement
    LockEvent      — push notification surfaced by the BLE client
    LogEntry       — one row from the lock's on-device operation log
    DeviceInfo     — standard BLE Device Information Service (0x180A) fields
    AutoLockLimits — the lock's own min/max allowed auto-lock delay
    FingerprintEntry — one enrolled fingerprint (see get_fingerprints's caveat)
    TTLockError    — raised by `TTLockClient` on BLE / protocol failure
    CloudError     — raised by `TTLockCloud` on a non-success HTTP response

IntEnums:
    AutoLockOperate, KeyboardPwdType, LockState, LockVolume, LogOperate, PwdOperateType
"""

from __future__ import annotations

from .client import TTLockClient
from .cloud import TTLockCloud
from .constants import (
    AutoLockOperate,
    KeyboardPwdType,
    LockState,
    LockVolume,
    LogOperate,
    PwdOperateType,
)
from .exceptions import CloudError, TTLockError
from .models import (
    AutoLockLimits,
    DeviceInfo,
    FingerprintEntry,
    LockAdvertisement,
    LockEvent,
    LockVersion,
    LogEntry,
    SiteInfo,
    VirtualKey,
)

__all__ = [
    "AutoLockLimits",
    "AutoLockOperate",
    "CloudError",
    "DeviceInfo",
    "FingerprintEntry",
    "KeyboardPwdType",
    "LockAdvertisement",
    "LockEvent",
    "LockState",
    "LockVersion",
    "LockVolume",
    "LogEntry",
    "LogOperate",
    "PwdOperateType",
    "SiteInfo",
    "TTLockClient",
    "TTLockCloud",
    "TTLockError",
    "VirtualKey",
]
