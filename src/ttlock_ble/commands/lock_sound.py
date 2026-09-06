"""Payloads and parser for CMD_SET_LOCK_SOUND (0x62) - the keypad/lock beep and its volume.

`COMM_AUDIO_MANAGE` in the official SDK, whose `audioManage` builder sends
`[0x01]` to read the setting and `[0x02][value…]` to change it. The write
forms were first captured from device traffic and confirmed against
physical locks; the SDK dump later matched them byte for byte.

On/off wire layout: `[0x02][0x00 or 0x01]` - 0x01 = sound on, 0x00 = off.

Volume wire layout: `[0x02][0x01][level: 1-5][0x00]` - confirmed via 5
independently-verified real-hardware writes, one per level, matching the
official app's Low/Medium-low/Medium/Medium-high/High. The 0x02 selector is
shared with the on/off form: one selector for sound-related settings,
distinguished by payload shape.

Read (SEARCH) wire layout, from the SDK's response parser rather than a
hardware capture: after the universal envelope, `[battery][op_echo=0x01]
[sound][volume]`, where `sound` is 0 for off and any other value for on, and
the trailing `volume` byte is present only on hardware that has the setting.

Both forms are admin-gated at the firmware level: sending them after only
CHECK_USER_TIME gets a FAILED status back - see `TTLockClient._admin_handshake`.
"""

from __future__ import annotations

from ..constants import LockVolume
from ..models import LockSound
from .envelope import RESPONSE_SUCCESS, parse_response_status

_SEARCH_OPERATION = 0x01
_MODIFY_OPERATION = 0x02
_VOLUME_SUBOP = 0x01
_VOLUME_TRAILER = 0x00
_SEARCH_MINIMUM_DATA_LENGTH = 3


def payload_get_lock_sound() -> bytes:
    """Build the CMD_SET_LOCK_SOUND SEARCH payload that reads the current setting."""
    return bytes([_SEARCH_OPERATION])


def payload_set_lock_sound(*, enabled: bool) -> bytes:
    """Build the CMD_SET_LOCK_SOUND payload. `enabled=True` turns sound on."""
    return bytes([_MODIFY_OPERATION, 0x01 if enabled else 0x00])


def _check_volume_level(level: int) -> None:
    # `LockVolume` is the one place that defines the valid range - checking
    # membership against it (not a hand-maintained min/max pair) means a
    # level added or removed there is picked up here automatically.
    if level not in LockVolume:
        raise ValueError(f"lock volume must be {min(LockVolume)}-{max(LockVolume)}, got {level}")


def payload_set_lock_volume(level: int) -> bytes:
    """Build the CMD_SET_LOCK_SOUND volume payload. `level` is 1-5 - see `LockVolume`."""
    _check_volume_level(level)
    return bytes([_MODIFY_OPERATION, _VOLUME_SUBOP, level, _VOLUME_TRAILER])


def parse_lock_sound_response(plaintext: bytes) -> LockSound:
    """Decode a CMD_SET_LOCK_SOUND SEARCH response into a `LockSound`.

    Raises `RuntimeError` on a FAILED status and `ValueError` when a SUCCESS
    response is too short to carry the battery, op-echo and sound bytes, or
    echoes an op-type other than SEARCH - a MODIFY ack carries no setting.
    The volume byte is optional and only kept when it names a `LockVolume`.
    """
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS:
        raise RuntimeError(f"audioManage FAILED: status={status:#x} err={data.hex()}")
    if len(data) < _SEARCH_MINIMUM_DATA_LENGTH:
        raise ValueError(f"audioManage SEARCH payload too short: {plaintext.hex()}")
    if data[1] != _SEARCH_OPERATION:
        raise ValueError(f"audioManage SEARCH expected op_echo=1, got {data[1]}: {plaintext.hex()}")
    reports_volume = len(data) > _SEARCH_MINIMUM_DATA_LENGTH and data[3] in LockVolume
    return LockSound(
        enabled=data[2] != 0,
        volume=LockVolume(data[3]) if reports_volume else None,
    )
