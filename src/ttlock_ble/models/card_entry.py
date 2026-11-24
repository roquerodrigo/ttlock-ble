"""CardEntry: one enrolled IC card (tag), as returned by `TTLockClient.get_cards`."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import datetime as dt

    from .validity import WeeklyWindow


@dataclass(frozen=True, slots=True)
class CardEntry:
    """One enrolled IC card (tag), decoded from the indexed CMD 0x05/0x01 query.

    The listing carries only the card's dates. Weekly windows live in a
    separate record set (CMD 0x70), which `TTLockClient.cards.list` reads
    into `weekly_windows` unless told not to. `None` there means they were
    not read, so the card may still be restricted; read them with
    `TTLockClient.weekly_schedules.get(Credential.of(entry))` before
    treating it as unrestricted. An empty tuple means the card has none.
    """

    card_id: bytes = field(repr=False)
    start_date: dt.datetime | None
    end_date: dt.datetime | None
    weekly_windows: tuple[WeeklyWindow, ...] | None = None

    @property
    def is_permanent(self) -> bool:
        """True if this card has no expiry date.

        Derived from `end_date` being the sentinel value observed on every
        card examined so far that the app itself labels "Permanent". Says
        nothing about weekly windows - see `weekly_windows`.
        """
        return self.end_date is None

    @property
    def has_explicit_start(self) -> bool:
        """True if a start date was ever set on this card.

        `False` means it is still at the "never explicitly set" sentinel
        observed, so far, on every fresh permanent or newly-enrolled
        timed card.
        """
        return self.start_date is not None
