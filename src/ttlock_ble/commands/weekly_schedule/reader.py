"""Sans-IO read of a credential's whole weekly schedule over the QUERY operation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ...exceptions import TTLockError
from .query_reply import parse_weekly_schedule_query_reply

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from .credential import CredentialType
    from .record import WeeklyScheduleRecord

MAX_RECORDS = 7


async def read_weekly_schedule(
    query: Callable[[int | None], Awaitable[bytes | None]],
    *,
    expected_credential: tuple[CredentialType, bytes] | None = None,
) -> list[WeeklyScheduleRecord]:
    """Walk the QUERY cursor and return the records in the order the lock reports them.

    `query(cursor)` sends one QUERY (`cursor=None` for the first) and returns
    the reply data after the `[0x70][status]` envelope, or `None` if no
    reply arrived. The walk stops when a returned position is not greater
    than the last cursor (the lock wrapped to its first record) or after 7
    records. `None` on the first query means the credential has no schedule
    and gives an empty list (a fingerprint without a schedule never
    replies; for a card this is not tested); `None` later raises
    `TTLockError`.

    Every reply must carry the same credential as the first one; if
    `expected_credential` (type and id) is given, every reply must match
    it, otherwise `TTLockError` is raised.

    Timeouts belong to the caller. Real replies arrive quickly, so use a
    short timeout for this query, otherwise every schedule-less
    fingerprint costs the full command timeout.
    """
    records: list[WeeklyScheduleRecord] = []
    cursor: int | None = None
    credential: tuple[int, bytes] | None = (
        None
        if expected_credential is None
        else (int(expected_credential[0]), expected_credential[1])
    )
    while len(records) < MAX_RECORDS:
        data = await query(cursor)
        if data is None:
            if not records:
                return records
            raise TTLockError(
                f"Failed to read weekly schedule: no reply after {len(records)} records"
            )
        try:
            reply = parse_weekly_schedule_query_reply(data)
        except ValueError as error:
            raise TTLockError(f"Failed to read weekly schedule: {error}") from error
        if cursor is not None and reply.position <= cursor:
            break
        reply_credential = (reply.credential_type, reply.credential_id)
        if credential not in (None, reply_credential):
            raise TTLockError("Failed to read weekly schedule: reply is for a different credential")
        credential = reply_credential
        records.append(reply.record)
        cursor = reply.position
    return records
