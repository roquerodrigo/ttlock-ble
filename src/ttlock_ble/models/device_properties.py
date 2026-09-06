"""DeviceProperties: the 6 confirmed TTLock-proprietary device properties."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import datetime as dt


@dataclass(frozen=True, slots=True)
class DeviceProperties:
    """The 6 confirmed fields read via `TTLockClient.get_device_properties` (CMD 0x90).

    Distinct from `DeviceInfo`: that one is the standard, unencrypted
    Bluetooth SIG Device Information Service; this is TTLock's own
    encrypted command protocol, confirmed on 3 physical locks across 2
    hardware families (models "SN484_PV53" and "SN478_PV53" on hardware
    "1.2", model "SN656-NS_PV53" on hardware "1.1"). The meaning of the
    "-NS" model suffix is an open question: "no speaker" was directly
    contradicted (that lock has a real beeper), and "has a keypad" does
    not distinguish it either (another tested lock has one too).

    Field names follow the official SDK's `DeviceInfoType` where it names
    the step: `manufacture_date` is its `MANUFACTURE_DATE` (kept as the
    opaque `factoryDate` string there too - the observed value does not
    decode as a calendar date). Steps 5 and 6 have no SDK name; `mac_address`
    and `clock_time` are what real hardware returns for them.
    """

    model_variant: str
    hardware_revision: str
    firmware_version: str
    manufacture_date: str
    mac_address: str
    clock_time: dt.datetime
