"""Weekday: the day numbering the lock uses in weekly credential schedules."""

from __future__ import annotations

from enum import IntEnum


class Weekday(IntEnum):
    """Day of the week as the lock numbers it, matching `datetime.isoweekday()`.

    Confirmed on hardware in the weekly-schedule records (CMD 0x70):
    1 is Monday and 7 is Sunday.
    """

    MONDAY = 1
    TUESDAY = 2
    WEDNESDAY = 3
    THURSDAY = 4
    FRIDAY = 5
    SATURDAY = 6
    SUNDAY = 7
