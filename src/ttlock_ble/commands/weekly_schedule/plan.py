"""Pure write plan for a weekly schedule: the payloads the official app sends."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .payloads import payload_weekly_schedule_add, payload_weekly_schedule_clear
from .record import WeeklyScheduleRecord

if TYPE_CHECKING:
    import datetime as dt
    from collections.abc import Mapping

    from .credential import CredentialType


def plan_weekly_schedule_write(
    credential_type: CredentialType,
    credential_id: bytes,
    day_windows: Mapping[int, tuple[dt.time, dt.time]],
) -> tuple[bytes, ...]:
    """Return CLEAR, then one ADD per day in weekday order (1 = Monday ... 7 = Sunday).

    `day_windows` maps each weekday to its `(start_time, end_time)`. This is
    the app's sequence for the 0x70 part of an edit (its validity update
    comes before, out of scope here). The plan sends no payload between
    steps, so the caller waits for each reply. An empty mapping is
    rejected: a CLEAR with no ADD was never captured, so what it would do
    to the credential is not tested. Each weekday has one window, as in
    the app; several windows on one weekday are not tested on hardware.
    Overnight windows (end before start) are not validated and not tested
    on hardware. Raises `ValueError` for an empty
    mapping or an invalid weekday or time.
    """
    if not day_windows:
        raise ValueError("day_windows must not be empty")
    records = [
        WeeklyScheduleRecord(weekday=weekday, start_time=start_time, end_time=end_time)
        for weekday, (start_time, end_time) in sorted(day_windows.items())
    ]
    return (
        payload_weekly_schedule_clear(credential_type, credential_id),
        *(
            payload_weekly_schedule_add(credential_type, credential_id, record)
            for record in records
        ),
    )
