"""Dataclass models for ttlock_ble: cloud and protocol record types."""

from __future__ import annotations

from .auto_lock_limits import AutoLockLimits
from .cloud_credentials import CloudCredentials
from .cyclic_schedule import CyclicSchedule
from .device_info import DeviceInfo
from .device_properties import DeviceProperties
from .fingerprint_entry import FingerprintEntry
from .lock_advertisement import LockAdvertisement
from .lock_event import LockEvent
from .lock_version import LockVersion
from .log_entry import LogEntry
from .passcode_entry import PasscodeEntry
from .site_info import SiteInfo
from .virtual_key import VirtualKey

__all__ = [
    "AutoLockLimits",
    "CloudCredentials",
    "CyclicSchedule",
    "DeviceInfo",
    "DeviceProperties",
    "FingerprintEntry",
    "LockAdvertisement",
    "LockEvent",
    "LockVersion",
    "LogEntry",
    "PasscodeEntry",
    "SiteInfo",
    "VirtualKey",
]
