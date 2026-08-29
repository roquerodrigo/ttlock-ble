"""Dataclass models for ttlock_ble: cloud and protocol record types."""

from __future__ import annotations

from .auto_lock_limits import AutoLockLimits
from .cloud_credentials import CloudCredentials
from .device_info import DeviceInfo
from .lock_advertisement import LockAdvertisement
from .lock_event import LockEvent
from .lock_version import LockVersion
from .log_entry import LogEntry
from .site_info import SiteInfo
from .virtual_key import VirtualKey

__all__ = [
    "AutoLockLimits",
    "CloudCredentials",
    "DeviceInfo",
    "LockAdvertisement",
    "LockEvent",
    "LockVersion",
    "LogEntry",
    "SiteInfo",
    "VirtualKey",
]
