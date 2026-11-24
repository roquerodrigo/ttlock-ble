"""WeeklyWindow: the hours a credential works on one day of the week."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ...constants import Weekday

if TYPE_CHECKING:
    import datetime as dt


@dataclass(frozen=True, slots=True)
class WeeklyWindow:
    """Valid on `weekday` from `start` until `end`, to the minute.

    A window stays inside one day: the lock stores a start and an end
    hour:minute per weekday, so one that crosses midnight is two windows
    on consecutive days. Seconds and time zones are ignored.
    """

    weekday: Weekday
    start: dt.time
    end: dt.time

    def __post_init__(self) -> None:
        """Reject a weekday or time range the lock cannot store."""
        object.__setattr__(self, "weekday", Weekday(self.weekday))
        if _minutes(self.start) >= _minutes(self.end):
            raise ValueError("weekly window must start before it ends, on the same day")


def _minutes(moment: dt.time) -> int:
    return moment.hour * 60 + moment.minute
