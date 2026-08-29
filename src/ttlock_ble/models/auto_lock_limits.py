"""AutoLockLimits: the allowed auto-lock delay range reported by the lock's own firmware."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AutoLockLimits:
    """Min/max auto-lock delay (seconds) `set_auto_lock_time` will accept.

    Confirmed via direct rejection testing on one physical lock, not
    just decoding the response: `min_allowed=1`, `max_allowed=900`
    (15 minutes) - `set_auto_lock_time` accepted every value in
    `[1, 900]` and the lock itself rejected anything above 900 (raised
    `TTLockError`). `0` (disable auto-lock) is a separate documented
    sentinel outside this range entirely - it is not validated against
    these limits and remains valid regardless of what they report.

    The SEARCH response carries one more byte after `max_allowed` whose
    meaning is unconfirmed - it stayed `0x01` across two very different
    current values (45s and 300s), suggesting it isn't tied to the
    current delay, but its actual purpose is unknown. Deliberately left
    undecoded here rather than guessed at.
    """

    min_allowed: int
    max_allowed: int
