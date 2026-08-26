"""DeviceInfo: standard BLE Device Information Service (0x180A) fields."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DeviceInfo:
    """Standard Bluetooth SIG Device Information Service (0x180A) fields.

    Read directly over plain GATT - unrelated to TTLock's own encrypted
    command protocol, the session AES key, or any TTLock account. Any
    BLE central can read these once connected, no handshake needed.

    Every field is `None` when the connected lock doesn't expose that
    characteristic. `manufacturer`, `model`, `hardware_revision` and
    `firmware_revision` are confirmed present on two physical locks: a
    Sciener SN484 (hardware 1.2, firmware 6.5.08.230228) and a Sciener
    SN534-4P-T78-BELL (hardware 1.7, firmware 6.5.20.24121101). Neither
    exposed `serial_number` or `software_revision` - both are
    implemented against the Bluetooth SIG spec but remain unconfirmed
    on real hardware.

    System ID (0x2A23) and PnP ID (0x2A50) are deliberately out of
    scope: unlike the fields above they are structured binary, not
    UTF-8 text, and decoding them has not been implemented or tested.
    """

    manufacturer: str | None = None
    model: str | None = None
    serial_number: str | None = None
    hardware_revision: str | None = None
    firmware_revision: str | None = None
    software_revision: str | None = None
