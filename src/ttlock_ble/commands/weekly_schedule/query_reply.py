"""WeeklyScheduleQueryReply and its parser for the weekly-schedule QUERY reply."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .operations import QUERY_OPERATION
from .record import RECORD_LENGTH, WeeklyScheduleRecord, decode_record

log: logging.Logger = logging.getLogger("ttlock_ble.weekly_schedule")

_HEADER_LENGTH = 6  # battery, operation echo, position (2), credential type, id_len


@dataclass(frozen=True, slots=True)
class WeeklyScheduleQueryReply:
    """One decoded QUERY reply.

    `credential_type` and `credential_id` are the raw wire values as echoed
    by the lock, not interpreted.
    """

    battery: int
    position: int
    credential_type: int
    credential_id: bytes
    record: WeeklyScheduleRecord


def parse_weekly_schedule_query_reply(data: bytes) -> WeeklyScheduleQueryReply:
    """Decode the data after the `[0x70][status]` envelope of a QUERY reply.

    Layout: `[battery][01][position:2][type][id_len][id][record:7]`. Raises
    `ValueError` on truncated data, a wrong operation echo, an `id_len`
    that overruns the data, or an invalid record. Bytes after the record
    are ignored with a debug log: replies come from one lock model only
    and other models are not tested.
    """
    if len(data) < _HEADER_LENGTH:
        raise ValueError(f"weekly schedule query reply too short: length={len(data)}")
    if data[1] != QUERY_OPERATION:
        raise ValueError(f"weekly schedule query reply echoes operation {data[1]:#04x}")
    credential_id_length = data[5]
    record_start = _HEADER_LENGTH + credential_id_length
    record_end = record_start + RECORD_LENGTH
    if len(data) < record_end:
        raise ValueError(
            "weekly schedule query reply truncated or id_len overruns the data: "
            f"length={len(data)} id_len={credential_id_length}"
        )
    if len(data) > record_end:
        log.debug(
            "Ignoring %d trailing bytes in weekly schedule query reply", len(data) - record_end
        )
    return WeeklyScheduleQueryReply(
        battery=data[0],
        position=int.from_bytes(data[2:4], "big"),
        credential_type=data[4],
        credential_id=bytes(data[_HEADER_LENGTH:record_start]),
        record=decode_record(data[record_start:record_end]),
    )
