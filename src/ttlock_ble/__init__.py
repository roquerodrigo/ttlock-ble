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
    DeviceProperties — 6 confirmed TTLock-proprietary device properties
    AutoLockLimits — the lock's own min/max allowed auto-lock delay
    FingerprintEntry — one enrolled fingerprint (see get_fingerprints's caveat)
    PasscodeEntry  — one keypad passcode (see get_passcodes's scope caveat)
    CyclicSchedule — the day-of-week/time-window rule behind a CIRCLE passcode
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
    CyclicSchedule,
    DeviceInfo,
    DeviceProperties,
    FingerprintEntry,
    LockAdvertisement,
    LockEvent,
    LockVersion,
    LogEntry,
    PasscodeEntry,
    SiteInfo,
    VirtualKey,
)

__all__ = [
    "AutoLockLimits",
    "AutoLockOperate",
    "CloudError",
    "CyclicSchedule",
    "DeviceInfo",
    "DeviceProperties",
    "FingerprintEntry",
    "KeyboardPwdType",
    "LockAdvertisement",
    "LockEvent",
    "LockState",
    "LockVersion",
    "LockVolume",
    "LogEntry",
    "LogOperate",
    "PasscodeEntry",
    "PwdOperateType",
    "SiteInfo",
    "TTLockClient",
    "TTLockCloud",
    "TTLockError",
    "VirtualKey",
]
