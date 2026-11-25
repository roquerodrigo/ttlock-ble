"""FingerprintEnrollmentStep: the moments of a fingerprint enrollment reported to `on_progress`."""

from __future__ import annotations

from enum import IntEnum


class FingerprintEnrollmentStep(IntEnum):
    """A moment of `FingerprintManager.enroll` worth telling the person at the lock about."""

    WAITING_FOR_FINGER = 1
    """The lock is in add mode: touch the sensor now."""
    TOUCH_RECORDED = 2
    """One more touch was recorded; more may be needed."""
    FINGERPRINT_READ = 3
    """The fingerprint was enrolled, and its validity applied if it has one."""
