"""Period: a credential valid between two moments."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ._lock_clock import check_date_range

if TYPE_CHECKING:
    import datetime as dt


@dataclass(frozen=True, slots=True)
class Period:
    """Valid from `start` until `end`, in the lock's local time, to the minute."""

    start: dt.datetime
    end: dt.datetime

    def __post_init__(self) -> None:
        """Reject a range the lock cannot store."""
        check_date_range("period", self.start, self.end)
