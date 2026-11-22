"""WeeklyScheduleRecord: one 7-byte record of the weekly-schedule command (CMD 0x70)."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

RECORD_LENGTH = 7
WEEKLY_KIND = 1
_WEEKDAY_MIN = 1
_WEEKDAY_MAX = 7
_BYTE_MAX = 0xFF


@dataclass(frozen=True, slots=True)
class WeeklyScheduleRecord:
    """One time window of a credential's weekly schedule.

    `weekday` is 1 = Monday ... 7 = Sunday (the same numbering as
    `datetime.date.isoweekday`). `kind` and `month` are the raw wire bytes:
    kind 1 is weekly with month 0; any other kind, and the meaning of the
    month byte, is not understood and is preserved unchanged. Validated on
    construction, so a record that exists can always be encoded.

    `start_time` and `end_time` carry hour and minute only; seconds and
    timezone must be unset.
    """

    weekday: int
    start_time: dt.time
    end_time: dt.time
    kind: int = WEEKLY_KIND
    month: int = 0

    def __post_init__(self) -> None:
        """Reject values the 7-byte wire layout cannot represent."""
        if not _WEEKDAY_MIN <= self.weekday <= _WEEKDAY_MAX:
            raise ValueError(f"weekday must be 1..7: {self.weekday}")
        for name, value in (("start_time", self.start_time), ("end_time", self.end_time)):
            if value.second or value.microsecond or value.tzinfo is not None:
                raise ValueError(f"{name} must carry hour and minute only: {value!r}")
        for name, byte in (("kind", self.kind), ("month", self.month)):
            if not 0 <= byte <= _BYTE_MAX:
                raise ValueError(f"{name} must fit in one byte: {byte}")


def encode_record(record: WeeklyScheduleRecord) -> bytes:
    """Encode a record as `[kind][weekday][month][start h][start min][end h][end min]`."""
    return bytes(
        [
            record.kind,
            record.weekday,
            record.month,
            record.start_time.hour,
            record.start_time.minute,
            record.end_time.hour,
            record.end_time.minute,
        ]
    )


def decode_record(data: bytes) -> WeeklyScheduleRecord:
    """Decode exactly 7 record bytes.

    Raises `ValueError` if the length is not 7 or any weekday, hour or
    minute is out of range.
    """
    if len(data) != RECORD_LENGTH:
        raise ValueError(
            f"weekly schedule record must be {RECORD_LENGTH} bytes: length={len(data)}"
        )
    kind, weekday, month, start_hour, start_minute, end_hour, end_minute = data
    try:
        return WeeklyScheduleRecord(
            weekday=weekday,
            start_time=dt.time(start_hour, start_minute),
            end_time=dt.time(end_hour, end_minute),
            kind=kind,
            month=month,
        )
    except ValueError as error:
        raise ValueError(f"invalid weekly schedule record {data.hex()}: {error}") from error
