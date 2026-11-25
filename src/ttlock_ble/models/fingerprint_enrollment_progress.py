"""FingerprintEnrollmentProgress: one progress report of `FingerprintManager.enroll`."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..constants import FingerprintEnrollmentStep


@dataclass(frozen=True, slots=True)
class FingerprintEnrollmentProgress:
    """Where an enrollment stands: the step, and how many touches the lock has recorded.

    The lock needs several touches of the same finger to learn it; both
    SN478_PV53 and SN484_PV53 locks asked for 4 (other models: not tested).
    `touches_required` is what the lock reports, never a constant.
    """

    step: FingerprintEnrollmentStep
    touches_recorded: int
    touches_required: int
