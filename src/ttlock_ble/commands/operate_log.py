"""Paging through the lock's on-device operation log (COMM_GET_OPERATE_LOG)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .encoding import decode_date6
from .envelope import RESPONSE_SUCCESS, parse_response_status
from .log_record import decode_log_record

if TYPE_CHECKING:
    from ..models import LogEntry


def payload_operate_log_request(sequence: int = 0xFFFF) -> bytes:
    """COMM_GET_OPERATE_LOG request — sequence number as UInt16 BE.

    `sequence=0xFFFF` (default) is the "since last sync" sentinel — the
    lock answers with the next record after its internal cursor. For
    each subsequent page pass back the `last_sequence` returned by
    `parse_operate_log_response` verbatim; the lock uses it as the
    cursor and advances by one record per call (matches
    `CommandUtil_V3.getOperateLog` in the TTLock Android SDK). Direction
    is firmware-dependent — observed DLock-XP V3 returns ascending
    sequences (oldest unread first).
    """
    return sequence.to_bytes(2, "big")


def parse_operate_log_response(plaintext: bytes) -> tuple[list[LogEntry], int]:
    """Decode COMM_GET_OPERATE_LOG into `(entries, last_sequence)`.

    Returns the decoded `LogEntry` list and the last sequence number
    observed (caller passes this back via `payload_operate_log_request`
    to fetch the next page). Returns an empty list when the lock has no
    new entries.
    """
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS or len(data) < 2:
        return [], 0
    total_len = int.from_bytes(data[:2], "big")
    if total_len == 0:
        return [], 0
    sequence = int.from_bytes(data[2:4], "big")
    entries: list[LogEntry] = []
    idx = 4
    while idx < len(data):
        rec_len = data[idx]
        idx += 1
        rec_start = idx
        if rec_start + rec_len > len(data):
            break
        record_type = data[idx]
        idx += 1
        operate_date = decode_date6(data[idx : idx + 6])
        idx += 6
        battery = data[idx]
        idx += 1
        entry = decode_log_record(
            record_type=record_type,
            operate_date=operate_date,
            battery=battery,
            sequence=sequence - len(entries) - 1,
            data=data,
            idx=idx,
            rec_end=rec_start + rec_len,
        )
        entries.append(entry)
        idx = rec_start + rec_len
    return entries, sequence
