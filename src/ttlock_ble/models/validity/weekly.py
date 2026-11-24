"""Weekly: a credential valid on chosen weekdays and hours, optionally inside a date range."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ._lock_clock import check_date_range

if TYPE_CHECKING:
    import datetime as dt

    from .weekly_window import WeeklyWindow


@dataclass(frozen=True, slots=True)
class Weekly:
    """Valid only during `windows`, and only between `start` and `end` when both are given.

    The lock keeps one window per weekday, so each weekday appears at most
    once; days without a window deny access. Leaving both bounds out
    repeats the windows indefinitely, which is the only form a weekly
    passcode can take: the lock stores no date range for it.
    """

    windows: tuple[WeeklyWindow, ...]
    start: dt.datetime | None = None
    end: dt.datetime | None = None

    def __post_init__(self) -> None:
        """Reject a range or a set of windows the lock cannot store."""
        if (self.start is None) != (self.end is None):
            raise ValueError("weekly validity needs both a start and an end, or neither")
        if self.start is not None and self.end is not None:
            check_date_range("weekly", self.start, self.end)
        object.__setattr__(self, "windows", tuple(self.windows))
        if not self.windows:
            raise ValueError("weekly validity needs at least one window")
        weekdays = [window.weekday for window in self.windows]
        if len(set(weekdays)) != len(weekdays):
            raise ValueError("weekly validity allows one window per weekday")

    @property
    def is_bounded(self) -> bool:
        """True when the windows only apply between `start` and `end`."""
        return self.start is not None
