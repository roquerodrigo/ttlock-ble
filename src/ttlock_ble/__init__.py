"""ttlock_ble: Python SDK for DLock-XP / TTLock smart locks over Bluetooth.

Public API:
    TTLockClient      — async BLE client for an already-paired lock
    TTLockCloud       — async HTTP client for the TTLock cloud (key bootstrap)
    CloudApp          — the OEM app identity the cloud client presents (see CLOUD_APPS)
    VirtualKey        — per-(user, lock) credential bundle
    LockVersion       — firmware identifiers used in the V3 frame header
    SiteInfo          — regional API endpoints (siteId, country, base URL)
    LockAdvertisement — bolt state + battery decoded from a BLE advertisement
    LockEvent         — push notification surfaced by the BLE client
    LockSound         — beep on/off and volume as read back from the lock
    LogEntry          — one row from the lock's on-device operation log
    DeviceFeatures    — the capability bits the lock itself reports (see LockFeature)
    DeviceInfo        — standard BLE Device Information Service (0x180A) fields
    DeviceProperties  — 6 confirmed TTLock-proprietary device properties
    AutoLockLimits    — the lock's own min/max allowed auto-lock delay
    FingerprintEntry  — one enrolled fingerprint (see get_fingerprints's caveat)
    CardEntry         — one enrolled IC card/tag (see get_cards's caveat)
    PasscodeEntry     — one keypad passcode (see get_passcodes's scope caveat)
    CyclicSchedule    — the day-of-week/time-window rule behind a CIRCLE passcode
    Validity          — when a credential is accepted: Permanent, Period, SingleUse or Weekly
    WeeklyWindow      — the hours a Weekly credential works on one weekday
    PasscodeManager   — `TTLockClient.passcodes`: list, add, modify, delete, clear
    AdminPasscodeManager — `TTLockClient.admin_passcode`: read and replace it
    TTLockError       — raised by `TTLockClient` on BLE / protocol failure
    LockRejectedError — the lock refused a command; `error_code` holds its reason
    CredentialAlreadyExistsError, CredentialNotFoundError, StorageFullError
                      — the refusals a credential command can map to
    UnsupportedFeatureError — the lock's feature mask lacks what a command needs
    CloudError        — raised by `TTLockCloud` on a non-success HTTP response

IntEnums:
    AutoLockOperate, KeyboardPwdType, LockErrorCode, LockFeature, LockState, LockVolume,
    LogOperate, PwdOperateType, Weekday
"""

from __future__ import annotations

from .client import TTLockClient
from .cloud import TTLockCloud
from .constants import (
    AutoLockOperate,
    KeyboardPwdType,
    LockErrorCode,
    LockFeature,
    LockState,
    LockVolume,
    LogOperate,
    PwdOperateType,
    Weekday,
)
from .credentials import AdminPasscodeManager, PasscodeManager
from .exceptions import (
    CloudError,
    CredentialAlreadyExistsError,
    CredentialNotFoundError,
    LockRejectedError,
    StorageFullError,
    TTLockError,
    UnsupportedFeatureError,
)
from .models import (
    CLOUD_APPS,
    AutoLockLimits,
    CardEntry,
    CloudApp,
    CyclicSchedule,
    DeviceFeatures,
    DeviceInfo,
    DeviceProperties,
    FingerprintEntry,
    LockAdvertisement,
    LockEvent,
    LockSound,
    LockVersion,
    LogEntry,
    PasscodeEntry,
    Period,
    Permanent,
    SingleUse,
    SiteInfo,
    Validity,
    VirtualKey,
    Weekly,
    WeeklyWindow,
)

__all__ = [
    "CLOUD_APPS",
    "AdminPasscodeManager",
    "AutoLockLimits",
    "AutoLockOperate",
    "CardEntry",
    "CloudApp",
    "CloudError",
    "CredentialAlreadyExistsError",
    "CredentialNotFoundError",
    "CyclicSchedule",
    "DeviceFeatures",
    "DeviceInfo",
    "DeviceProperties",
    "FingerprintEntry",
    "KeyboardPwdType",
    "LockAdvertisement",
    "LockErrorCode",
    "LockEvent",
    "LockFeature",
    "LockRejectedError",
    "LockSound",
    "LockState",
    "LockVersion",
    "LockVolume",
    "LogEntry",
    "LogOperate",
    "PasscodeEntry",
    "PasscodeManager",
    "Period",
    "Permanent",
    "PwdOperateType",
    "SingleUse",
    "SiteInfo",
    "StorageFullError",
    "TTLockClient",
    "TTLockCloud",
    "TTLockError",
    "UnsupportedFeatureError",
    "Validity",
    "VirtualKey",
    "Weekday",
    "Weekly",
    "WeeklyWindow",
]
