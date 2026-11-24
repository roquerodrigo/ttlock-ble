"""WeeklyScheduleManager: the weekdays and hours a card or fingerprint works (CMD 0x70)."""

from __future__ import annotations

import datetime as dt
import logging
from typing import TYPE_CHECKING

from ..commands import weekly_schedule as schedule
from ..commands.envelope import RESPONSE_SUCCESS, parse_response_status
from ..constants import LockErrorCode, LockFeature, Weekday
from ..exceptions import (
    CredentialNotFoundError,
    ReplyTimeoutError,
    TTLockError,
    rejection_error,
)
from ..models import Weekly, WeeklyWindow

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from ..models import Credential
    from .admin_channel import AdminChannel

log: logging.Logger = logging.getLogger("ttlock_ble.credentials")

_WEEKLY_SCHEDULE = 0x70
# Real replies take about 0.1 s; a credential without records gets none at all.
_QUERY_TIMEOUT = 2.0


class WeeklyScheduleManager:
    """Weekly windows of cards and fingerprints, reached as `TTLockClient.weekly_schedules`.

    A credential with windows only works during them, and only inside its
    own validity dates, which these calls leave untouched. Every method
    needs `CYCLIC_IC_OR_FINGER_PRINT`. Passcodes carry their schedule
    differently - see `PasscodeManager.add`.

    Confirmed on SN484 and SN534 locks: windows are written with one CLEAR
    and one ADD per weekday, as the official app does, and read back one
    record per QUERY. A credential without windows gets no reply to a QUERY
    and the lock stops answering until the link is reopened, which `get`
    does on its own.
    """

    def __init__(self, channel: AdminChannel) -> None:
        """Bind the manager to the client's admin channel."""
        self._channel = channel

    async def get(self, credential: Credential) -> tuple[WeeklyWindow, ...]:
        """Read a credential's windows in weekday order; empty when it has none.

        An empty answer costs about two seconds plus a reconnect, and is the
        same for a credential the lock does not hold.
        """
        async with self._channel.session():
            await self._channel.require(
                "get_weekly_schedule", LockFeature.CYCLIC_IC_OR_FINGER_PRINT
            )
            unanswered = False

            async def query(cursor: int | None) -> bytes | None:
                nonlocal unanswered
                payload = schedule.payload_weekly_schedule_query(
                    credential.kind, credential.identifier, cursor
                )
                try:
                    plain = await self._channel.query(
                        _WEEKLY_SCHEDULE, payload, "get_weekly_schedule", timeout=_QUERY_TIMEOUT
                    )
                except ReplyTimeoutError:
                    unanswered = True
                    return None
                return _success_data(plain, "get_weekly_schedule")

            try:
                records = await schedule.read_weekly_schedule(
                    query, expected_credential=(credential.kind, credential.identifier)
                )
            finally:
                if unanswered:
                    await self._channel.reopen()
        windows = tuple(_window(record) for record in records)
        log.info("weekly schedule: %d window(s)", len(windows))
        return tuple(sorted(windows, key=lambda window: window.weekday))

    async def set(self, credential: Credential, windows: Iterable[WeeklyWindow]) -> None:
        """Replace a credential's windows; at most one per weekday, each inside one day.

        An empty set is refused: use `clear` to lift the restriction. The
        lock answers success even for a credential it does not hold.
        """
        weekly = Weekly(tuple(windows))
        payloads = schedule.plan_weekly_schedule_write(
            credential.kind,
            credential.identifier,
            {
                window.weekday: (_minute(window.start), _minute(window.end))
                for window in weekly.windows
            },
        )
        clear, *adds = payloads
        async with self._channel.session():
            await self._channel.require(
                "set_weekly_schedule", LockFeature.CYCLIC_IC_OR_FINGER_PRINT
            )
            await self._clear(clear)
            for add in adds:
                data = await self._channel.command(_WEEKLY_SCHEDULE, add, "set_weekly_schedule")
                _check(schedule.parse_weekly_schedule_add_reply, data, "set_weekly_schedule")

    async def clear(self, credential: Credential) -> None:
        """Remove every window, so the credential works whenever its dates allow.

        Clearing a credential without windows, or one the lock does not
        hold, is not an error: the lock gives both the same answer.
        """
        payload = schedule.payload_weekly_schedule_clear(credential.kind, credential.identifier)
        async with self._channel.session():
            await self._channel.require(
                "clear_weekly_schedule", LockFeature.CYCLIC_IC_OR_FINGER_PRINT
            )
            await self._clear(payload)

    async def _clear(self, payload: bytes) -> None:
        try:
            data = await self._channel.command(_WEEKLY_SCHEDULE, payload, "clear_weekly_schedule")
        except CredentialNotFoundError as error:
            if error.error_code != LockErrorCode.RECORD_NOT_EXIST:
                raise
            log.debug("weekly schedule already empty")
            return
        _check(schedule.parse_weekly_schedule_clear_reply, data, "clear_weekly_schedule")


def _success_data(plain: bytes, action: str) -> bytes:
    try:
        _echo, status, data = parse_response_status(plain)
    except ValueError as error:
        raise TTLockError(f"Failed to {action}: {error}") from None
    if status != RESPONSE_SUCCESS:
        raise rejection_error(action, data[0] if data else None)
    return data


def _check(
    parser: Callable[[bytes], schedule.WeeklyScheduleWriteReply], data: bytes, action: str
) -> None:
    try:
        parser(data)
    except ValueError as error:
        raise TTLockError(f"Failed to {action}: {error}") from None


def _minute(moment: dt.time) -> dt.time:
    return dt.time(moment.hour, moment.minute)


def _window(record: schedule.WeeklyScheduleRecord) -> WeeklyWindow:
    if record.kind != schedule.WEEKLY_KIND or record.month:
        raise TTLockError(
            f"Failed to get_weekly_schedule: record kind {record.kind} month {record.month} "
            "is not a weekly window"
        )
    return WeeklyWindow(Weekday(record.weekday), record.start_time, record.end_time)
