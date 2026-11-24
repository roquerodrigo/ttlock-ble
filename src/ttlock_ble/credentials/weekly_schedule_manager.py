"""WeeklyScheduleManager: the weekdays and hours a card or fingerprint works (CMD 0x70)."""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
from typing import TYPE_CHECKING

from .. import commands as cmd
from ..commands import weekly_schedule as schedule
from ..constants import LockErrorCode, LockFeature, Weekday
from ..exceptions import CredentialNotFoundError, ReplyTimeoutError, TTLockError
from ..models import Weekly, WeeklyWindow

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from ..models import Credential
    from .admin_channel import AdminChannel

# Logged under `ttlock_ble.client`, like every other lock command, so one
# log-level filter covers the whole conversation with the lock.
log: logging.Logger = logging.getLogger("ttlock_ble.client")

# Real replies take about 0.1 s; a credential without records gets none at all.
DEFAULT_QUERY_TIMEOUT = 2.0


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

    async def get(
        self,
        credential: Credential,
        *,
        timeout: float = DEFAULT_QUERY_TIMEOUT,  # noqa: ASYNC109 -- the lock's silence is the answer, so the deadline is part of the call
    ) -> tuple[WeeklyWindow, ...]:
        """Read a credential's windows in weekday order; empty when it has none.

        The lock answers a credential without windows - or one it does not
        hold - with silence, so an empty result really means "no reply
        within `timeout`". Raise `timeout` on a slow link (a busy proxy),
        where a late reply would otherwise read as "unrestricted". An empty
        answer also costs a reconnect, done here; `disconnected_callback`
        does not fire for it.
        """
        async with self._channel.session():
            await self._channel.require(
                "get_weekly_schedule", LockFeature.CYCLIC_IC_OR_FINGER_PRINT
            )
            unanswered = False

            async def query(cursor: int | None) -> bytes | None:
                nonlocal unanswered
                payload = schedule.payload_weekly_schedule_query(
                    credential.credential_type, credential.identifier, cursor
                )
                try:
                    return await self._channel.command(
                        cmd.CMD_WEEKLY_SCHEDULE, payload, "get_weekly_schedule", timeout=timeout
                    )
                except ReplyTimeoutError:
                    unanswered = True
                    return None
                except asyncio.CancelledError:
                    unanswered = True
                    raise

            try:
                records = await schedule.read_weekly_schedule(
                    query, expected_credential=(credential.credential_type, credential.identifier)
                )
            finally:
                if unanswered:
                    await self._channel.reopen()
        windows = sorted((_window(record) for record in records), key=lambda window: window.weekday)
        log.info("weekly schedule: %d window(s)", len(windows))
        return tuple(windows)

    async def set(self, credential: Credential, windows: Iterable[WeeklyWindow]) -> None:
        """Replace a credential's windows; at most one per weekday, each inside one day.

        An empty set is refused: use `clear` to lift the restriction. The
        lock answers success even for a credential it does not hold.

        The write is a CLEAR followed by one ADD per weekday, so a failure
        part-way leaves the credential with fewer windows than asked - with
        none, it works around the clock. Such a failure raises
        `TTLockError` saying how many windows were written; read the
        result back with `get` before relying on it.
        """
        weekly = Weekly(tuple(windows))
        clear, *adds = schedule.plan_weekly_schedule_write(
            credential.credential_type,
            credential.identifier,
            {
                window.weekday: (_minute(window.start), _minute(window.end))
                for window in weekly.windows
            },
        )
        async with self._channel.session():
            await self._channel.require(
                "set_weekly_schedule", LockFeature.CYCLIC_IC_OR_FINGER_PRINT
            )
            await self._clear(clear)
            for written, add in enumerate(adds):
                try:
                    data = await self._channel.command(
                        cmd.CMD_WEEKLY_SCHEDULE, add, "set_weekly_schedule"
                    )
                    _check(schedule.parse_weekly_schedule_add_reply, data, "set_weekly_schedule")
                except TTLockError as error:
                    raise TTLockError(
                        f"Failed to set_weekly_schedule: windows cleared, only {written} of "
                        f"{len(adds)} written back: {error}"
                    ) from error

    async def clear(self, credential: Credential) -> None:
        """Remove every window, so the credential works whenever its dates allow.

        Clearing a credential without windows, or one the lock does not
        hold, is not an error: the lock gives both the same answer.
        """
        payload = schedule.payload_weekly_schedule_clear(
            credential.credential_type, credential.identifier
        )
        async with self._channel.session():
            await self._channel.require(
                "clear_weekly_schedule", LockFeature.CYCLIC_IC_OR_FINGER_PRINT
            )
            await self._clear(payload)

    async def _clear(self, payload: bytes) -> None:
        try:
            data = await self._channel.command(
                cmd.CMD_WEEKLY_SCHEDULE, payload, "clear_weekly_schedule"
            )
        except CredentialNotFoundError as error:
            if error.error_code != LockErrorCode.RECORD_NOT_EXIST:
                raise
            log.debug("weekly schedule already empty")
            return
        _check(schedule.parse_weekly_schedule_clear_reply, data, "clear_weekly_schedule")


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
    try:
        return WeeklyWindow(Weekday(record.weekday), record.start_time, record.end_time)
    except ValueError:
        raise TTLockError(
            f"Failed to get_weekly_schedule: the {Weekday(record.weekday).name.title()} window "
            "does not end after it starts"
        ) from None
