"""LockSound: the keypad/lock beep setting as reported by `TTLockClient.get_lock_sound`."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..constants import LockVolume


@dataclass(frozen=True, slots=True)
class LockSound:
    """Beep on/off plus, on speaker-equipped hardware, its `LockVolume` level.

    `volume` is `None` when the lock does not report one: the audio SEARCH
    response carries the volume byte only on hardware that has the setting,
    and a reported level outside `LockVolume` is treated the same way rather
    than surfaced as a bogus value.
    """

    enabled: bool
    volume: LockVolume | None
