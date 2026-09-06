"""CyclicSchedule: the day-of-week/time-window rule behind a CIRCLE-type keypad passcode."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CyclicSchedule:
    """A recurring day-of-week (or preset) time window, decoded from a CIRCLE passcode.

    `day_or_preset` is one of the individual weekday names ("Monday" ..
    "Sunday") or one of the multi-day presets the official app itself
    offers ("Daily", "Workdays", "Weekend"). `start_hour`/`start_minute`
    are literal wall-clock values on the wire, not sentinels;
    `duration_hours` is derived from the wire's
    `low_byte - base_selector + 1` - there is no separate end-time field.

    Confirmed via 8 independent real examples, each cross-checked against
    the app's own displayed schedule - except Wednesday, Thursday and
    Friday's underlying base selector, which are formula-predicted only
    (`(iso_weekday + 1) * 24`) and have never been independently verified
    on real hardware. A genuine multi-day combination that isn't one of
    the named presets above was never tested; whether it would follow a
    bitmask or something else entirely is unknown.

    Assumes whole-hour durations and that the window ends on the same
    minute it starts (`end_minute == start_minute` implicitly, since
    there is no separate end_minute field) - every confirmed real example
    started on the hour with a whole-hour duration. A schedule with a
    non-zero start minute, or a fractional-hour duration, was never
    tested and may not decode correctly.
    """

    day_or_preset: str
    start_hour: int
    start_minute: int
    duration_hours: int

    @property
    def end_hour(self) -> int:
        """Wall-clock hour (0-23) this window ends, derived from `start_hour + duration_hours`."""
        return (self.start_hour + self.duration_hours) % 24
