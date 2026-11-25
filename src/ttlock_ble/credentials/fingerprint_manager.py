"""FingerprintManager: list, enroll, change and remove fingerprints (CMD 0x06)."""

from __future__ import annotations

import dataclasses
import logging
import time
from typing import TYPE_CHECKING

from .. import commands as cmd
from ..constants import CredentialType, FingerprintEnrollmentStep, LockFeature
from ..exceptions import (
    EnrollmentTimeoutError,
    FingerprintEnrolledLateError,
    LinkLostError,
    LockRejectedError,
    ReplyTimeoutError,
    TTLockError,
    UnsupportedFeatureError,
)
from ..models import Credential, FingerprintEnrollmentProgress, Permanent, Weekly

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence

    from ..models import FingerprintEntry, Validity, WeeklyWindow
    from .admin_channel import AdminChannel
    from .weekly_schedule_manager import WeeklyScheduleManager

    ProgressCallback = Callable[[FingerprintEnrollmentProgress], None]

# Logged under `ttlock_ble.client`, like every other lock command, so one
# log-level filter covers the whole conversation with the lock.
log: logging.Logger = logging.getLogger("ttlock_ble.client")

# Well above the 200 fingerprints a lock holds; only a runaway cursor gets here.
_MAX_FINGERPRINT_ENTRIES = 300

# How long a person has by default to finish an enrollment, counted from the command.
DEFAULT_ENROLL_TIMEOUT = 30.0

# How long `enroll` waits for each reply from the lock, whatever the caller's deadline.
# The lock always ends add mode itself, with the "enrolled" push or an error about 8.4 s
# after the last touch (SN478_PV53), so this only guards against a dead link and is
# comfortably longer than that. Every reply restarts it.
LOCK_REPLY_TIMEOUT = 15.0

# The error byte of the lock's own enrollment timeout (SN478_PV53). Its meaning is not in
# the SDK material available to us: it is named after what was observed, so it stays out
# of `LockErrorCode`.
_ENROLLMENT_TIMED_OUT = 0xE4


class FingerprintManager:
    """Fingerprints on one lock, reached as `TTLockClient.fingerprints`.

    Every method is admin-gated and validates its input before touching the
    BLE link. Fingerprint ids never reach logs, reprs or exception messages.
    Fingerprints can be `Permanent`, a `Period`, or `Weekly` (windows on
    chosen weekdays, inside optional dates); a fingerprint has no single-use
    form, so `SingleUse` raises `ValueError`. A fingerprint cannot be added by
    its id - the lock has to read the finger - so there is no `add`.

    Everything except `list` needs the `FINGER_PRINT` feature, and a `Weekly`
    validity also needs `CYCLIC_IC_OR_FINGER_PRINT`. Fingerprints are
    addressed with a `Credential`: `Credential.fingerprint(identifier)` with
    the 6-byte id, or `Credential.of(entry)` for a listed one; any other kind
    of credential raises `ValueError` before the lock is contacted.

    Run by this SDK on an SN478_PV53 lock (firmware 6.4.43.240529): enrolling
    (progress and the new id), no finger placed (the lock's own error 0xE4),
    a finger completing after a 3 s deadline (deleted and reported with
    `FingerprintEnrolledLateError`; with no finger the call waited for the
    lock's own error), `modify` to a future `Period` (the finger was rejected),
    to `Permanent` with the listing dates (the finger was accepted) and to a
    weekly window (the finger was rejected outside it), deleting one
    fingerprint, and clearing all. Run on an SN484_PV53 lock (firmware
    6.5.15.240522): enrolling, deleting one fingerprint and clearing all. The
    official app's captures of both models match the payloads built here;
    enrolling a finger that is already enrolled was captured on the SN478_PV53.

    Not tested: whether a deleted fingerprint's weekly windows go with it,
    cancelling the call or dropping the link before the lock's final answer,
    whether `LOCK_REPLY_TIMEOUT` suffices on slower locks, and other lock models.
    """

    def __init__(self, channel: AdminChannel, weekly_schedules: WeeklyScheduleManager) -> None:
        """Bind the manager to the client's admin channel and its weekly-window manager."""
        self._channel = channel
        self._weekly_schedules = weekly_schedules

    async def list(self, *, include_weekly_windows: bool = True) -> list[FingerprintEntry]:
        """Read every enrolled fingerprint, with its weekly windows unless told not to.

        One round trip per fingerprint, following the lock's own list cursor:
        the first query sends position 0 and each reply's position is sent
        back as the next query, so the lock answers with the next fingerprint
        after it. Positions skip deleted fingerprints - counting 0, 1, 2, ...
        would list the one after a gap twice (confirmed on SN478_PV53). Stops
        at the lock's end-of-list reply, or when a reply's position does not
        advance (a repeat of an entry already listed); raises `TTLockError`
        if neither happens within `_MAX_FINGERPRINT_ENTRIES` queries. Not
        gated on a feature.

        With `include_weekly_windows` each entry's `weekly_windows` holds what
        `WeeklyScheduleManager.get` reads. A fingerprint without windows gets
        no reply to that query, so each one costs a short timeout and a
        reconnect: pass `False` for a fast listing, which leaves
        `weekly_windows` as `None` ("not read") - a fingerprint listed that
        way may still be restricted. On a lock without
        `CYCLIC_IC_OR_FINGER_PRINT` none can have windows, so none are read
        and every entry gets an empty tuple.
        """
        entries: list[FingerprintEntry] = []
        async with self._channel.session():
            position = 0
            for _ in range(_MAX_FINGERPRINT_ENTRIES):
                plain = await self._channel.query(
                    cmd.CMD_MANAGE_FINGERPRINT,
                    cmd.payload_fingerprint_list(position),
                    "get_fingerprints",
                )
                log.debug("fingerprint list response: length=%d", len(plain))
                try:
                    page = cmd.parse_fingerprint_list_page(plain)
                except (RuntimeError, ValueError) as error:
                    raise TTLockError(f"Failed to get_fingerprints: {error}") from None
                if page is None:
                    break
                entry, reply_position = page
                if reply_position <= position:
                    break
                entries.append(entry)
                position = reply_position
            else:
                raise TTLockError(
                    f"Failed to get_fingerprints: exceeded safety cap of "
                    f"{_MAX_FINGERPRINT_ENTRIES} entries without an end-of-list response"
                )
        log.info("fetched %d fingerprint(s)", len(entries))
        if include_weekly_windows:
            return [*await self._with_weekly_windows(entries)]
        return entries

    async def enroll(
        self,
        validity: Validity | None = None,
        on_progress: ProgressCallback | None = None,
        *,
        timeout: float = DEFAULT_ENROLL_TIMEOUT,  # noqa: ASYNC109 -- the lock's silence is the answer, so the deadline is part of the call
    ) -> Credential:
        """Enroll the finger someone places on the lock, permanent unless `validity` says otherwise.

        Puts the lock in add mode and waits for the person to touch the
        sensor several times. `on_progress` receives a
        `FingerprintEnrollmentProgress`: `WAITING_FOR_FINGER` when the lock is
        ready - the moment to tell the person to start - then `TOUCH_RECORDED`
        after each touch with `touches_recorded` of `touches_required` (both
        models captured ask for 4), and `FINGERPRINT_READ` once the finger was
        enrolled and its validity applied. It must not block. Returns the new
        fingerprint's `Credential`, which the other methods take.

        `timeout` is the person's deadline in seconds, counted from the command;
        it decides what a result means, not how long the conversation lasts.
        The lock keeps add mode open while touches continue and always ends it
        itself, with the "enrolled" push or, about 8.4 s without a touch, an
        error. Confirmed on SN478_PV53 with a client that stopped listening at a
        3 s timeout: it disconnected, and the lock still completed the enrollment when the
        finger was placed four times afterwards, as a new permanent fingerprint.
        With the behaviour described here, run on SN478_PV53 with a 3 s
        deadline, a finger completing afterwards was deleted and reported
        with `FingerprintEnrolledLateError`, and with no finger the call
        waited for the lock's own error.
        So the call keeps the connection and keeps reading, and reports
        progress, past `timeout` until the lock ends add mode; each reply is
        waited for at most `LOCK_REPLY_TIMEOUT`, which only guards against a
        dead link. Then:

        - the lock's error because no finger came: `EnrollmentTimeoutError`;
        - the finger completed before `timeout`: the fingerprint is returned;
        - the finger completed after `timeout`: the new fingerprint is deleted
          at once and `FingerprintEnrolledLateError` says so, and whether the
          delete worked. Do not call that a success. It can only be the new
          entry, since an enrollment always returns a new id.

        A link that stays silent for `LOCK_REPLY_TIMEOUT` after the lock was
        ready raises `EnrollmentTimeoutError` (before that, a plain
        `ReplyTimeoutError`); the lock may still be in add mode and enroll a
        finger. A link the lock drops after it was ready raises
        `EnrollmentTimeoutError` at once and leaves the client disconnected;
        a finger completed in that gap may be enrolled, so list the
        fingerprints after reconnecting. Neither case is tested on hardware,
        nor is cancelling the call before the lock's answer.

        A permanent fingerprint needs nothing more. Otherwise its validity is
        applied right after the last touch, as the official app does: `Period`
        and `Weekly` send their dates (an unbounded `Weekly` sends those of a
        permanent fingerprint), and `Weekly` then writes its windows with
        `WeeklyScheduleManager.set`. If either step fails, the fingerprint
        would stay permanent and unrestricted, so it is deleted again and a
        `TTLockError` reports the original failure and whether the delete
        worked - never retried silently. Another command from the same client
        may run between the steps. A cancelled call is not rolled back: list
        the fingerprints afterwards.

        Enrolling a finger that is already enrolled is not detected, and the
        lock does not report it: it is answered like a new enrollment and
        creates a second, separate, permanent entry with a new id (captured on
        SN478_PV53). The existing entry keeps its dates and windows, but the
        finger then opens the lock through the new entry - outside the old
        one's restrictions. The official app does not notice this either. If
        the person may already be enrolled, list the fingerprints first and
        delete or restrict the new entry. Because an enrollment always returns
        a new id, a rollback never touches an entry that existed before.

        Raises `StorageFullError` when the lock has no room left, and
        `UnsupportedFeatureError` without `FINGER_PRINT` (and, for `Weekly`,
        `CYCLIC_IC_OR_FINGER_PRINT`).
        """
        validity = validity or Permanent()
        cmd.check_fingerprint_validity(validity)
        failure: TTLockError | None = None
        async with self._channel.session():
            await self._require_fingerprints("enroll_fingerprint", validity)
            credential, required, late = await self._wait_for_finger(on_progress, timeout)
            if late:
                raise await self._remove_late(credential, timeout)
            if not isinstance(validity, Permanent):
                failure = await self._try(
                    self._apply_dates(credential, validity, "enroll_fingerprint")
                )
        if failure is None and isinstance(validity, Weekly):
            failure = await self._try(self._weekly_schedules.set(credential, validity.windows))
        if failure is not None:
            raise await self._roll_back(credential, failure, "enroll_fingerprint")
        if on_progress is not None:
            on_progress(
                FingerprintEnrollmentProgress(
                    FingerprintEnrollmentStep.FINGERPRINT_READ, required, required
                )
            )
        return credential

    async def _wait_for_finger(
        self,
        on_progress: ProgressCallback | None,
        timeout: float,  # noqa: ASYNC109 -- the caller's deadline, only compared with the clock
    ) -> tuple[Credential, int, bool]:
        """Enter add mode inside the caller's session; return the fingerprint, touches, lateness."""
        waiting = False
        fingerprint_id = b""
        required = 0
        late = False
        started = time.monotonic()

        def on_reply(data: bytes) -> bool:
            nonlocal waiting, fingerprint_id, required, late
            try:
                reply = cmd.parse_fingerprint_enrollment_reply(data)
            except ValueError as error:
                raise TTLockError(f"Failed to enroll_fingerprint: {error}") from None
            if isinstance(reply, bytes):
                fingerprint_id = reply
                late = time.monotonic() - started > timeout
                return True
            waiting = True
            required = reply.touches_required
            if on_progress is not None:
                on_progress(reply)
            return False

        try:
            await self._channel.command(
                cmd.CMD_MANAGE_FINGERPRINT,
                cmd.payload_fingerprint_enroll(),
                "enroll_fingerprint",
                on_reply=on_reply,
                timeout=LOCK_REPLY_TIMEOUT,
            )
        except LockRejectedError as error:
            if error.error_code != _ENROLLMENT_TIMED_OUT:
                raise
            raise EnrollmentTimeoutError(
                "Failed to enroll_fingerprint: the lock ended add mode because the finger "
                "was not placed in time"
            ) from error
        except ReplyTimeoutError as error:
            if not waiting:
                raise
            raise _unanswered_enrollment(error) from error
        log.info("fingerprint enrolled")
        return Credential(CredentialType.FINGERPRINT, fingerprint_id), required, late

    async def _remove_late(
        self,
        credential: Credential,
        timeout: float,  # noqa: ASYNC109 -- only reported
    ) -> TTLockError:
        """Delete a fingerprint enrolled after the deadline, in the session; describe it."""
        try:
            await self._channel.command(
                cmd.CMD_MANAGE_FINGERPRINT,
                cmd.payload_fingerprint_delete(credential.identifier),
                "delete_fingerprint",
            )
        except TTLockError as error:
            log.warning("late fingerprint could not be removed")
            return FingerprintEnrolledLateError(
                f"Failed to enroll_fingerprint: a finger completed enrollment after the "
                f"{timeout:g} s timeout and was enrolled as permanent, and deleting it failed "
                f"({error}); it may still open the lock - list the fingerprints and delete it",
                removed=False,
            )
        log.warning("late fingerprint removed")
        return FingerprintEnrolledLateError(
            f"Failed to enroll_fingerprint: a finger completed enrollment after the "
            f"{timeout:g} s timeout and the new fingerprint was removed again",
            removed=True,
        )

    async def modify(self, fingerprint: Credential, validity: Validity) -> None:
        """Change a fingerprint's validity, replacing its dates and its weekly windows.

        `Period` sets its dates. `Weekly` sets its dates (an unbounded one
        those of a permanent fingerprint) and then its windows. `Permanent`
        sends the dates the lock lists for a permanent entry, 2000-01-01 00:00
        to 2099-01-01 00:00; the lock then accepted the finger (SN478_PV53).
        A `Period` starting in the future rejected it until then, and a
        `Weekly` window rejected it outside the window (SN478_PV53). Any
        validity but `Weekly` also clears the fingerprint's windows, which is not an
        error when it has none.

        If writing the windows fails after the dates were changed, the dates
        stay changed and the fingerprint may have fewer windows than asked
        (see `WeeklyScheduleManager.set`); read it back with `list`.

        Raises `ValueError` for a credential that is not a fingerprint, and
        `CredentialNotFoundError` if the lock does not hold it.
        """
        payload = cmd.payload_fingerprint_modify(_fingerprint_id(fingerprint), validity)
        async with self._channel.session():
            await self._require_fingerprints("modify_fingerprint", validity)
            await self._channel.command(cmd.CMD_MANAGE_FINGERPRINT, payload, "modify_fingerprint")
        if isinstance(validity, Weekly):
            await self._weekly_schedules.set(fingerprint, validity.windows)
            return
        try:
            await self._weekly_schedules.clear(fingerprint)
        except UnsupportedFeatureError:
            log.debug("lock has no weekly windows to clear")

    async def delete(self, fingerprint: Credential) -> None:
        """Remove one fingerprint.

        Raises `ValueError` for a credential that is not a fingerprint, and
        `CredentialNotFoundError` if the lock does not hold it. Its weekly
        windows go with it; not tested.
        """
        payload = cmd.payload_fingerprint_delete(_fingerprint_id(fingerprint))
        async with self._channel.session():
            await self._channel.require("delete_fingerprint", LockFeature.FINGER_PRINT)
            await self._channel.command(cmd.CMD_MANAGE_FINGERPRINT, payload, "delete_fingerprint")

    async def clear(self) -> None:
        """Remove EVERY fingerprint from the lock. There is no undo."""
        async with self._channel.session():
            await self._channel.require("clear_fingerprints", LockFeature.FINGER_PRINT)
            await self._channel.command(
                cmd.CMD_MANAGE_FINGERPRINT, cmd.payload_fingerprint_clear(), "clear_fingerprints"
            )

    async def _require_fingerprints(self, action: str, validity: Validity) -> None:
        await self._channel.require(action, LockFeature.FINGER_PRINT)
        if isinstance(validity, Weekly):
            await self._channel.require(action, LockFeature.CYCLIC_IC_OR_FINGER_PRINT)

    async def _apply_dates(self, credential: Credential, validity: Validity, action: str) -> None:
        payload = cmd.payload_fingerprint_modify(credential.identifier, validity)
        await self._channel.command(cmd.CMD_MANAGE_FINGERPRINT, payload, action)

    async def _with_weekly_windows(
        self, entries: Sequence[FingerprintEntry]
    ) -> tuple[FingerprintEntry, ...]:
        with_windows: tuple[FingerprintEntry, ...] = ()
        supported = True
        for entry in entries:
            windows: tuple[WeeklyWindow, ...] = ()
            if supported:
                try:
                    windows = await self._weekly_schedules.get(Credential.of(entry))
                except UnsupportedFeatureError:
                    supported = False
            with_windows += (dataclasses.replace(entry, weekly_windows=windows),)
        return with_windows

    @staticmethod
    async def _try(step: Awaitable[object]) -> TTLockError | None:
        try:
            await step
        except TTLockError as error:
            return error
        return None

    async def _roll_back(
        self, credential: Credential, failure: TTLockError, action: str
    ) -> TTLockError:
        """Delete a fingerprint whose validity could not be applied and describe both outcomes."""
        try:
            async with self._channel.session():
                await self._channel.command(
                    cmd.CMD_MANAGE_FINGERPRINT,
                    cmd.payload_fingerprint_delete(credential.identifier),
                    "delete_fingerprint",
                )
        except TTLockError as error:
            log.warning("fingerprint rollback failed")
            outcome = (
                f"deleting the new fingerprint also failed ({error}); it may remain enrolled "
                "as a permanent, unrestricted fingerprint - list the fingerprints and delete it"
            )
        else:
            log.warning("fingerprint rolled back")
            outcome = "the new fingerprint was deleted again"
        wrapped = TTLockError(f"Failed to {action}: {failure}; {outcome}")
        wrapped.__cause__ = failure
        return wrapped


def _fingerprint_id(fingerprint: Credential) -> bytes:
    if fingerprint.credential_type != CredentialType.FINGERPRINT:
        raise ValueError("expected a fingerprint credential")
    return fingerprint.identifier


def _unanswered_enrollment(error: ReplyTimeoutError) -> EnrollmentTimeoutError:
    if isinstance(error, LinkLostError):
        return EnrollmentTimeoutError(
            "Failed to enroll_fingerprint: the lock dropped the link during enrollment; a "
            "finger completed meanwhile may have been enrolled - reconnect and list the "
            "fingerprints"
        )
    return EnrollmentTimeoutError(
        "Failed to enroll_fingerprint: no reply from the lock within "
        f"{LOCK_REPLY_TIMEOUT:g} s; it may still be in add mode"
    )
