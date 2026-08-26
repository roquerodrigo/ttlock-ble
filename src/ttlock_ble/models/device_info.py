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
    characteristic. Confirmed present on the one physical lock this was
    tested against (a Sciener SN484, hardware 1.2, firmware
    6.5.08.230228): `manufacturer`, `model`, `hardware_revision`,
    `firmware_revision`. `serial_number` and `software_revision` are
    implemented against the Bluetooth SIG spec but were not exposed by
    that lock's GATT table, so they remain unconfirmed on real hardware
    - expected to generalize to other lock models, not verified to.

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
