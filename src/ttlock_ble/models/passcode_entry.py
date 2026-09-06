"""PasscodeEntry: one keypad passcode, as returned by `TTLockClient.get_passcodes`."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..constants import KeyboardPwdType

if TYPE_CHECKING:
    import datetime as dt

    from .cyclic_schedule import CyclicSchedule


@dataclass(frozen=True, slots=True)
class PasscodeEntry:
    """One keypad passcode, decoded from the CMD 0x07 sequential query.

    See `TTLockClient.get_passcodes` for the critical scope limitation -
    this is not an exhaustive list of every passcode active on the lock.

    `start_date`/`end_date` are only populated for `PERMANENT`/`PERIOD`
    passcodes: `end_date` stays `None` for a permanent code (whose
    `start_date` is itself always the sentinel in every example seen),
    and both stay `None` for a `CIRCLE` code, which carries its own
    `cyclic_schedule` instead. `cyclic_schedule` is only set for `CIRCLE`
    passcodes - see `CyclicSchedule` for what that model does and
    doesn't cover.

    `passcode` is the wire's `new_pwd` field - the current value, and
    identical to the wire's `pwd` field unless the code was changed since
    creation. No captured example has shown the two differ, so which one
    actually reflects "the code that unlocks the door today" is an
    assumption, not something independently confirmed.
    """

    passcode: str
    pwd_type: KeyboardPwdType
    start_date: dt.datetime | None
    end_date: dt.datetime | None
    cyclic_schedule: CyclicSchedule | None

    @property
    def is_permanent(self) -> bool:
        """True if this is a `PERMANENT`-type passcode (no expiry, no schedule)."""
        return self.pwd_type == KeyboardPwdType.PERMANENT
