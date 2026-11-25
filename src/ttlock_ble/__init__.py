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
    FingerprintEnrollmentProgress — one progress report of a fingerprint enrollment
    CardEntry         — one enrolled IC card/tag (see get_cards's caveat)
    PasscodeEntry     — one keypad passcode (see get_passcodes's scope caveat)
    CyclicSchedule    — the day-of-week/time-window rule behind a CIRCLE passcode
    Validity          — when a credential is accepted: Permanent, Period, SingleUse or Weekly
    WeeklyWindow      — the hours a Weekly credential works on one weekday
    CardManager       — `TTLockClient.cards`: list, enroll, add, modify, delete, clear
    FingerprintManager — `TTLockClient.fingerprints`: list, enroll, modify, delete, clear
    PasscodeManager   — `TTLockClient.passcodes`: list, add, modify, delete, clear
    AdminPasscodeManager — `TTLockClient.admin_passcode`: read and replace it
    WeeklyScheduleManager — `TTLockClient.weekly_schedules`: card and fingerprint windows
    Credential        — a card or fingerprint as the lock addresses it
    TTLockError       — raised by `TTLockClient` on BLE / protocol failure
    LockRejectedError — the lock refused a command; `error_code` holds its reason
    CredentialAlreadyExistsError, CredentialNotFoundError, StorageFullError
                      — the refusals a credential command can map to
    UnsupportedFeatureError — the lock's feature mask lacks what a command needs
    ReplyTimeoutError — the lock did not answer a command in time
    LinkLostError     — the lock dropped the BLE link before answering a command
    EnrollmentTimeoutError — no card or finger was presented while the lock waited for one
    CardPresentedLateError — a card was tapped after the timeout and was removed again
    FingerprintEnrolledLateError — a finger completed enrollment after the timeout and was removed
    CardAlreadyEnrolledError — the card was already on the lock (enroll restored it, add refused)
    CloudError        — raised by `TTLockCloud` on a non-success HTTP response

IntEnums:
    AutoLockOperate, CardEnrollmentStep, CredentialType, FingerprintEnrollmentStep,
    KeyboardPwdType, LockErrorCode, LockFeature, LockState, LockVolume, LogOperate,
    PwdOperateType, Weekday
"""

from __future__ import annotations

from .client import TTLockClient
from .cloud import TTLockCloud
from .constants import (
    AutoLockOperate,
    CardEnrollmentStep,
    CredentialType,
    FingerprintEnrollmentStep,
    KeyboardPwdType,
    LockErrorCode,
    LockFeature,
    LockState,
    LockVolume,
    LogOperate,
    PwdOperateType,
    Weekday,
)
from .credentials import (
    AdminPasscodeManager,
    CardManager,
    FingerprintManager,
    PasscodeManager,
    WeeklyScheduleManager,
)
from .exceptions import (
    CardAlreadyEnrolledError,
    CardPresentedLateError,
    CloudError,
    CredentialAlreadyExistsError,
    CredentialNotFoundError,
    EnrollmentTimeoutError,
    FingerprintEnrolledLateError,
    LinkLostError,
    LockRejectedError,
    ReplyTimeoutError,
    StorageFullError,
    TTLockError,
    UnsupportedFeatureError,
)
from .models import (
    CLOUD_APPS,
    AutoLockLimits,
    CardEntry,
    CloudApp,
    Credential,
    CyclicSchedule,
    DeviceFeatures,
    DeviceInfo,
    DeviceProperties,
    FingerprintEnrollmentProgress,
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
    "CardAlreadyEnrolledError",
    "CardEnrollmentStep",
    "CardEntry",
    "CardManager",
    "CardPresentedLateError",
    "CloudApp",
    "CloudError",
    "Credential",
    "CredentialAlreadyExistsError",
    "CredentialNotFoundError",
    "CredentialType",
    "CyclicSchedule",
    "DeviceFeatures",
    "DeviceInfo",
    "DeviceProperties",
    "EnrollmentTimeoutError",
    "FingerprintEnrolledLateError",
    "FingerprintEnrollmentProgress",
    "FingerprintEnrollmentStep",
    "FingerprintEntry",
    "FingerprintManager",
    "KeyboardPwdType",
    "LinkLostError",
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
    "ReplyTimeoutError",
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
    "WeeklyScheduleManager",
    "WeeklyWindow",
]
