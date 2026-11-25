"""FingerprintEntry: one enrolled fingerprint, as returned by `TTLockClient.get_fingerprints`."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import datetime as dt

    from .validity import WeeklyWindow


@dataclass(frozen=True, slots=True)
class FingerprintEntry:
    """One enrolled fingerprint, decoded from the indexed CMD 0x06/0x06 query.

    The listing carries only the fingerprint's dates. Weekly windows live in
    a separate record set (CMD 0x70), which `TTLockClient.fingerprints.list`
    reads into `weekly_windows` unless told not to. `None` there means they
    were not read, so the fingerprint may still be restricted; read them with
    `TTLockClient.weekly_schedules.get(Credential.of(entry))` before treating
    it as unrestricted. An empty tuple means the fingerprint has none.
    """

    fingerprint_id: bytes = field(repr=False)
    slot: int = field(repr=False)
    start_date: dt.datetime | None
    end_date: dt.datetime | None
    weekly_windows: tuple[WeeklyWindow, ...] | None = None

    @property
    def identifier(self) -> bytes:
        """The 6-byte id the lock addresses this fingerprint by when changing or deleting it.

        The lock sends one 6-byte id; `fingerprint_id` holds its first four
        bytes and `slot` the last two, a split kept for compatibility.
        """
        return self.fingerprint_id + self.slot.to_bytes(2, "big")

    @property
    def is_permanent(self) -> bool:
        """True if this fingerprint has no expiry date.

        Derived from `end_date` being the sentinel value seen for every
        fingerprint the app itself labels "Permanent". Says nothing about
        weekly windows - see `weekly_schedules.get`.
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
