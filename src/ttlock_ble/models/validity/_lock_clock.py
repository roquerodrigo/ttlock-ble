"""Shared checks for the wall-clock values a lock stores with minute precision."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import datetime as dt

_FIRST_LOCK_YEAR = 2000
_LAST_LOCK_YEAR = 2099


def lock_minute(moment: dt.datetime) -> dt.datetime:
    """Return `moment`'s displayed wall-clock fields, naive and truncated to the minute.

    The lock stores year-to-minute fields with no offset, so an aware
    datetime contributes the time it displays, not the instant it denotes,
    the same way `TTLockClient.calibrate_time` reads it.
    """
    return moment.replace(tzinfo=None, second=0, microsecond=0)


def check_date_range(kind: str, start: dt.datetime, end: dt.datetime) -> None:
    """Raise `ValueError` unless `start` is before `end` and both fit the lock's calendar."""
    for moment in (start, end):
        if not _FIRST_LOCK_YEAR <= moment.year <= _LAST_LOCK_YEAR:
            raise ValueError(
                f"{kind} validity must fall between {_FIRST_LOCK_YEAR} and "
                f"{_LAST_LOCK_YEAR}, got year {moment.year}"
            )
    if lock_minute(start) >= lock_minute(end):
        raise ValueError(f"{kind} validity must start before it ends, to the minute")
