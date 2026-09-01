"""FingerprintEntry: one enrolled fingerprint, as returned by `TTLockClient.get_fingerprints`."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import datetime as dt


@dataclass(frozen=True, slots=True)
class FingerprintEntry:
    """One enrolled fingerprint, decoded from the indexed CMD 0x06/0x06 query.

    Known limitation: this cannot detect whether a fingerprint also has a
    cyclic (day-of-week/time-range) restriction - that data lives in a
    separate mechanism (CMD 0x70) this class doesn't query. A fingerprint
    shown here as permanent or timed may in practice also be restricted
    to specific days/hours. Do not treat the absence of that information
    as confirmation a fingerprint is unrestricted.
    """

    fp_id: bytes
    slot: int
    start_date: dt.datetime | None
    end_date: dt.datetime | None

    @property
    def is_permanent(self) -> bool:
        """True if this fingerprint has no expiry date.

        Derived from `end_date` being the sentinel value seen for every
        fingerprint the app itself labels "Permanent". Says nothing about
        cyclic (day-of-week/time-range) restrictions - a permanent
        fingerprint can still be cyclically restricted via a separate
        mechanism this class doesn't cover; see the class docstring.
        """
        return self.end_date is None

    @property
    def has_explicit_start(self) -> bool:
        """True if a start date was ever set on this fingerprint.

        `False` means it is still at the "never explicitly set" sentinel
        every fresh permanent or newly-enrolled timed fingerprint carries
        by default.
        """
        return self.start_date is not None
