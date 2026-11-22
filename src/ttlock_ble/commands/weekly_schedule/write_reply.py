"""WeeklyScheduleWriteReply and the parsers for the CLEAR and ADD replies."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .operations import ADD_OPERATION, CLEAR_OPERATION

log: logging.Logger = logging.getLogger("ttlock_ble.weekly_schedule")

_WRITE_REPLY_LENGTH = 2


@dataclass(frozen=True, slots=True)
class WeeklyScheduleWriteReply:
    """A CLEAR or ADD reply: the battery byte and the raw echoed operation byte."""

    battery: int
    operation: int


def _parse_write_reply(data: bytes, expected_operation: int) -> WeeklyScheduleWriteReply:
    if len(data) < _WRITE_REPLY_LENGTH:
        raise ValueError(f"weekly schedule write reply too short: length={len(data)}")
    if len(data) > _WRITE_REPLY_LENGTH:
        log.debug(
            "Ignoring %d trailing bytes in weekly schedule write reply",
            len(data) - _WRITE_REPLY_LENGTH,
        )
    if data[1] != expected_operation:
        raise ValueError(
            f"weekly schedule write reply echoes operation {data[1]:#04x}, "
            f"expected {expected_operation:#04x}"
        )
    return WeeklyScheduleWriteReply(battery=data[0], operation=data[1])


def parse_weekly_schedule_clear_reply(data: bytes) -> WeeklyScheduleWriteReply:
    """Decode a CLEAR reply `[battery][04]`.

    Raises `ValueError` if truncated or on a wrong echo; trailing bytes are ignored.
    """
    return _parse_write_reply(data, CLEAR_OPERATION)


def parse_weekly_schedule_add_reply(data: bytes) -> WeeklyScheduleWriteReply:
    """Decode an ADD reply `[battery][02]`.

    Raises `ValueError` if truncated or on a wrong echo; trailing bytes are ignored.
    """
    return _parse_write_reply(data, ADD_OPERATION)
