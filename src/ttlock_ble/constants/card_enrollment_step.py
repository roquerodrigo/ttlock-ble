"""CardEnrollmentStep: the moments of an enrollment by tap reported to `on_progress`."""

from __future__ import annotations

from enum import IntEnum


class CardEnrollmentStep(IntEnum):
    """A moment of `CardManager.enroll` worth telling the person at the lock about."""

    WAITING_FOR_CARD = 1
    """The lock is in add mode: present the card now."""
    CARD_READ = 2
    """The card was enrolled, and its validity applied if it has one."""
