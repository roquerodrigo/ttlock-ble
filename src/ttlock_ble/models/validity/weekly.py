"""Weekly: a credential valid on chosen weekdays and hours, inside a date range."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ._lock_clock import check_date_range

if TYPE_CHECKING:
    import datetime as dt

    from .weekly_window import WeeklyWindow


@dataclass(frozen=True, slots=True)
class Weekly:
    """Valid from `start` until `end`, and inside that range only during `windows`.

    The lock keeps one window per weekday, so each weekday appears at most
    once; days without a window deny access.
    """

    start: dt.datetime
    end: dt.datetime
    windows: tuple[WeeklyWindow, ...]

    def __post_init__(self) -> None:
        """Reject a range or a set of windows the lock cannot store."""
        check_date_range("weekly", self.start, self.end)
        object.__setattr__(self, "windows", tuple(self.windows))
        if not self.windows:
            raise ValueError("weekly validity needs at least one window")
        weekdays = [window.weekday for window in self.windows]
        if len(set(weekdays)) != len(weekdays):
            raise ValueError("weekly validity allows one window per weekday")
