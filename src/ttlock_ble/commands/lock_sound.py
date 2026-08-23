"""Payload for CMD_SET_LOCK_SOUND (0x62) - toggles the keypad/lock beep.

Reverse-engineered from device traffic rather than from the official SDK
dump the rest of this package mirrors: captured with the gateway offline
(forcing a direct phone-to-lock BLE session), decrypted with the already-
cached per-lock AES key, then confirmed by sending the same frame from
this library directly against a physical lock and listening for the
beep to actually change, in both directions.

Wire layout: `[selector][0x00 or 0x01]`. The second byte is fully
confirmed - 0x01 = sound on, 0x00 = sound off. The selector byte
(0x02 here) is only confirmed to be "constant across every capture and
required for a SUCCESS response" - it may be a fixed magic byte for this
command, or a selector for other switch-type settings under the same
opcode; only the sound selector has been tested, so this module
deliberately doesn't generalize past that.

Confirmed admin-gated at the firmware level, not just by the official
app's UI: sending it after only CHECK_USER_TIME (the plain handshake
unlock()/lock() use) - deliberately skipping CHECK_ADMIN + CHECK_RANDOM -
gets a FAILED status back from the lock. See
`TTLockClient._admin_handshake`.

Write-only: no opcode that reports the current sound setting back has
been found, so `TTLockClient.set_lock_sound` cannot be verified against
the lock afterward - see its docstring.
"""

from __future__ import annotations

_SOUND_SELECTOR = 0x02


def payload_set_lock_sound(*, enabled: bool) -> bytes:
    """Build the CMD_SET_LOCK_SOUND payload. `enabled=True` turns sound on."""
    return bytes([_SOUND_SELECTOR, 0x01 if enabled else 0x00])
