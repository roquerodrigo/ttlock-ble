"""CardEntry: one enrolled IC card (tag), as returned by `TTLockClient.get_cards`."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import datetime as dt


@dataclass(frozen=True, slots=True)
class CardEntry:
    """One enrolled IC card (tag), decoded from the indexed CMD 0x05/0x01 query.

    Known limitation: this cannot detect whether a card also has a
    cyclic (day-of-week/time-range) restriction - CMD 0x70, the
    mechanism that carries that data for every credential type, is not
    implemented anywhere in this library yet. A card shown here as
    permanent or timed may in practice also be restricted to specific
    days/hours. Do not treat the absence of that information as
    confirmation a card is unrestricted.
    """

    card_id: bytes
    start_date: dt.datetime | None
    end_date: dt.datetime | None

    @property
    def is_permanent(self) -> bool:
        """True if this card has no expiry date.

        Derived from `end_date` being the sentinel value observed on every
        card examined so far that the app itself labels "Permanent". Says
        nothing about
        cyclic (day-of-week/time-range) restrictions - a permanent card
        can still be cyclically restricted via a separate mechanism
        this class doesn't cover; see the class docstring.
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
