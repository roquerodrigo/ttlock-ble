"""TTLock-proprietary device properties - CMD 0x90, steps 1-6 (a fixed, indexed query).

Reverse-engineered from device traffic, confirmed on 3 physical locks across
2 hardware families. Distinct from the standard BLE Device Information
Service (see `models.DeviceInfo`): this is TTLock's own encrypted command
protocol, exposing different data, and gated behind the admin handshake -
see `TTLockClient.get_device_properties`.

`step` starts at 1, not 0, and only 6 steps are confirmed valid: step 7
cleanly errors with 0x19 ("unrecognized step") on every lock tested, so the
client sends exactly steps 1 through 6 rather than probing for an
end-of-list. Unlike the auto-lock or fingerprint responses, there is no
leading battery byte here - `data` is each step's raw payload directly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .encoding import decode_date6, decode_mac6, decode_null_terminated_ascii
from .envelope import RESPONSE_SUCCESS, parse_response_status

if TYPE_CHECKING:
    import datetime as dt

_ERROR_UNRECOGNIZED_STEP = 0x19


def payload_device_property(step: int) -> bytes:
    """Build the CMD 0x90 payload for one property step (1-6)."""
    return bytes([step])


def _property_data(plaintext: bytes) -> bytes:
    """Return the raw data payload for one CMD 0x90 response, or raise.

    Raises `RuntimeError` on a FAILED status; a confirmed 0x19 error code
    ("unrecognized step") is called out explicitly rather than left as an
    opaque hex byte.
    """
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS:
        code = data[0] if data else None
        if code == _ERROR_UNRECOGNIZED_STEP:
            raise RuntimeError(
                f"unrecognized device property step (0x19): status={status:#x} err={data.hex()}"
            )
        raise RuntimeError(f"device property query FAILED: status={status:#x} err={data.hex()}")
    return data


def parse_device_property_string(plaintext: bytes) -> str:
    """Decode a step 1-4 response: a null-terminated ASCII string.

    Confirmed exact plaintexts: step 1 is the model variant (e.g.
    "SN478_PV53"), step 2 the hardware revision (cross-confirmed against
    the standard BLE Device Information Service), step 3 a firmware
    version string, step 4 a hardware/serial ID.
    """
    return decode_null_terminated_ascii(_property_data(plaintext))


def parse_device_property_mac(plaintext: bytes) -> str:
    """Decode the step 5 response: the lock's own BLE MAC, byte-reversed on the wire.

    Confirmed via cross-device testing (3 locks): the decoded address
    matched each lock's real MAC exactly. Uppercased to match
    `VirtualKey.lockMac`; `decode_mac6` stays lowercase for its other
    callers, so the uppercasing happens here rather than in that shared
    helper.
    """
    return decode_mac6(_property_data(plaintext)).upper()


def parse_device_property_clock(plaintext: bytes) -> dt.datetime:
    """Decode the step 6 response: the lock's current RTC, same 6-byte format as `calibrate_time`.

    Confirmed as the real "current lock time" - verified against
    wall-clock time across multiple sequential reads on three locks.
    Raises `ValueError` if the bytes don't decode to a valid calendar date.
    """
    data = _property_data(plaintext)
    parsed = decode_date6(data[:6])
    if parsed is None:
        raise ValueError(f"device property clock not a valid date: {plaintext.hex()}")
    return parsed
