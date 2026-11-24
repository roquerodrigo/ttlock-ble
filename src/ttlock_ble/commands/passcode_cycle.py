"""The 16-bit cycle type that schedules a weekly (CIRCLE) keypad passcode.

Derived from the lock's own CIRCLE entries in the passcode list and confirmed
by writing schedules back through RECOVERY (including a start on minute 30):
the value is
`1000 + 24 * preset + (duration_hours - 1)`, and the window's start time
travels separately, in the hour and minute bytes of the date before it.
"""

from __future__ import annotations

import datetime as dt
from typing import TYPE_CHECKING

from ..constants import Weekday

if TYPE_CHECKING:
    from ..models import Weekly

_CYCLE_TYPE_BASE = 1000
_HOURS_PER_PRESET = 24
_WEEKDAYS = frozenset(Weekday)
_WORKDAYS = frozenset(Weekday) - {Weekday.SATURDAY, Weekday.SUNDAY}
_WEEKEND = frozenset({Weekday.SATURDAY, Weekday.SUNDAY})
_WEEKEND_PRESET = 0
_DAILY_PRESET = 1
_WORKDAYS_PRESET = 2
_FIRST_WEEKDAY_PRESET = 3


def encode_passcode_cycle(weekly: Weekly) -> tuple[dt.time, int]:
    """Return the window start and the cycle type a weekly passcode is written with.

    The lock keeps one window shared by every selected day, so all windows
    must start and end at the same time; the days must be one weekday,
    Monday to Friday, Saturday and Sunday, or the whole week; the window
    must last whole hours; and the passcode cannot be limited to a date
    range. Anything else raises `ValueError` naming what the lock cannot
    express.
    """
    if weekly.is_bounded:
        raise ValueError("a weekly passcode cannot be limited to a date range")
    window = weekly.windows[0]
    if any((other.start, other.end) != (window.start, window.end) for other in weekly.windows):
        raise ValueError("a weekly passcode uses the same hours on every day")
    duration_minutes = (window.end.hour * 60 + window.end.minute) - (
        window.start.hour * 60 + window.start.minute
    )
    if duration_minutes % 60:
        raise ValueError("a weekly passcode window must last whole hours")
    preset = _preset({window.weekday for window in weekly.windows})
    cycle_type = _CYCLE_TYPE_BASE + _HOURS_PER_PRESET * preset + duration_minutes // 60 - 1
    return dt.time(window.start.hour, window.start.minute), cycle_type


def _preset(weekdays: set[Weekday]) -> int:
    if weekdays == _WEEKDAYS:
        return _DAILY_PRESET
    if weekdays == _WORKDAYS:
        return _WORKDAYS_PRESET
    if weekdays == _WEEKEND:
        return _WEEKEND_PRESET
    if len(weekdays) == 1:
        return _FIRST_WEEKDAY_PRESET + next(iter(weekdays)) - Weekday.MONDAY
    raise ValueError(
        "a weekly passcode covers one weekday, Monday to Friday, the weekend or every day"
    )
