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
    hardware families (Garage: model "SN484_PV53", hardware "1.2";
    TestBenchLock: model "SN478_PV53", hardware "1.2"; Laundry: model
    "SN656-NS_PV53", hardware "1.1"). Laundry - the one lock known to
    have an additional keypad - is the one with a structurally different
    model number and hardware revision; the "-NS" suffix's meaning is an
    open question - an initial "no speaker" guess was directly
    contradicted (Laundry has a real beeper), and "has a keypad" doesn't
    distinguish it either (TestBenchLock also has one).
    """

    model_variant: str
    hardware_revision: str
    firmware_version: str
    hardware_id: str
    mac_address: str
    clock_time: dt.datetime
