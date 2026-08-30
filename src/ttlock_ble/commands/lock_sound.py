"""Payloads for CMD_SET_LOCK_SOUND (0x62) - keypad/lock beep and, on capable hardware, its volume.

Reverse-engineered from device traffic rather than from the official SDK
dump the rest of this package mirrors: captured with the gateway offline
(forcing a direct phone-to-lock BLE session), decrypted with the already-
cached per-lock AES key, then confirmed by sending the same frame from
this library directly against a physical lock and listening for the
beep to actually change, in both directions.

On/off wire layout: `[selector][0x00 or 0x01]`. The second byte is fully
confirmed - 0x01 = sound on, 0x00 = sound off.

Volume wire layout: `[selector][0x01][level: 1-5][0x00]` - confirmed via
5 independently-verified real-hardware writes, one per level, all
decoding cleanly and sequentially (matching the official app's
Low/Medium-low/Medium/Medium-high/High). The selector byte (0x02 here)
is shared with the on/off form rather than being volume-specific - real
hardware settled what used to be an open question in this module: it's
one selector for sound-related settings under this opcode, distinguished
by payload length/shape, not a different selector per setting.

Confirmed admin-gated at the firmware level, not just by the official
app's UI: sending either form after only CHECK_USER_TIME (the plain
handshake unlock()/lock() use) - deliberately skipping CHECK_ADMIN +
CHECK_RANDOM - gets a FAILED status back from the lock. See
`TTLockClient._admin_handshake`.

Write-only: no opcode that reports the current sound setting or volume
back has been found, so neither `TTLockClient.set_lock_sound` nor
`TTLockClient.set_lock_volume` can be verified against the lock
afterward - see their docstrings.
"""

from __future__ import annotations

from ..constants import LockVolume

_SOUND_SELECTOR = 0x02
_VOLUME_SUBOP = 0x01
_VOLUME_TRAILER = 0x00


def payload_set_lock_sound(*, enabled: bool) -> bytes:
    """Build the CMD_SET_LOCK_SOUND payload. `enabled=True` turns sound on."""
    return bytes([_SOUND_SELECTOR, 0x01 if enabled else 0x00])


def _check_volume_level(level: int) -> None:
    # `LockVolume` is the one place that defines the valid range - checking
    # membership against it (not a hand-maintained min/max pair) means a
    # level added or removed there is picked up here automatically.
    if level not in LockVolume:
        raise ValueError(f"lock volume must be {min(LockVolume)}-{max(LockVolume)}, got {level}")


def payload_set_lock_volume(level: int) -> bytes:
    """Build the CMD_SET_LOCK_SOUND volume payload. `level` is 1-5 - see `LockVolume`."""
    _check_volume_level(level)
    return bytes([_SOUND_SELECTOR, _VOLUME_SUBOP, level, _VOLUME_TRAILER])
