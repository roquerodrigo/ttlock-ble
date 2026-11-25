"""CardManager: list, enroll, add, change and remove IC cards (CMD 0x05)."""

from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import logging
import time
from typing import TYPE_CHECKING

from .. import commands as cmd
from ..constants import CardEnrollmentStep, CredentialType, LockFeature
from ..exceptions import (
    CardAlreadyEnrolledError,
    CardPresentedLateError,
    EnrollmentTimeoutError,
    LinkLostError,
    LockRejectedError,
    ReplyTimeoutError,
    TTLockError,
    UnsupportedFeatureError,
)
from ..models import Credential, Period, Permanent, Weekly

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence

    from ..models import CardEntry, Validity, WeeklyWindow
    from .admin_channel import AdminChannel
    from .weekly_schedule_manager import WeeklyScheduleManager

    ProgressCallback = Callable[[CardEnrollmentStep], None]

# Logged under `ttlock_ble.client`, like every other lock command, so one
# log-level filter covers the whole conversation with the lock.
log: logging.Logger = logging.getLogger("ttlock_ble.client")

# Well above what any lock holds; only a runaway cursor gets here.
_MAX_CARD_ENTRIES = 300

# How long `enroll` waits for the lock's answer and then for a card by default.
# The lock sends nothing when its own wait ends, so this is the only limit.
DEFAULT_ENROLL_TIMEOUT = 30.0

# After `enroll` gives up, the lock may still be in add mode and would enroll a
# card as a permanent one. Measured on an SN484_PV53 lock: a card presented 10 s
# after the command was enrolled, one at 20 s was rejected. Other models: not
# tested. `enroll` keeps listening this long, counted from the command.
ENROLL_SAFETY_WINDOW = 30.0


class _LinkDroppedInAddMode(Exception):  # noqa: N818 -- a private signal, never raised to callers
    """The lock dropped the link after entering add mode; the link was already reopened."""

    def __init__(self, started: float) -> None:
        super().__init__()
        self.started = started


class CardManager:
    """IC cards (tags) on one lock, reached as `TTLockClient.cards`.

    Every method is admin-gated and validates its input before touching
    the BLE link. Card numbers never reach logs or exception messages.
    Cards can be `Permanent`, a `Period`, or `Weekly` (windows on chosen
    weekdays, inside optional dates); a card has no single-use form, so
    `SingleUse` raises `ValueError`.

    Everything except `list` needs the `IC` feature, and a `Weekly`
    validity also needs `CYCLIC_IC_OR_FINGER_PRINT`. Cards are addressed
    with a `Credential`: `Credential.card(number)`, or `Credential.of(entry)`
    for a listed card; any other kind of credential raises `ValueError`
    before the lock is contacted.

    Confirmed on an SN484_PV53 lock (firmware 6.5.15.240522), from the
    official app's captures and from hardware runs of this SDK: enrolling
    by tap (permanent, dated and weekly), adding by number, changing a
    card's validity, deleting one card, clearing all, and removing a card
    presented after the enrollment timeout.

    Presenting or adding a card the lock already holds resets it there:
    adding it again replaces its dates (a card limited to ten days became
    permanent), and tapping it in add mode is reported exactly like a new
    enrollment while the lock makes its dates permanent and wipes its
    weekly windows. The official app does not detect the second case - a
    capture shows it reporting success while the card lost both. `add`
    therefore refuses a held card and `enroll` restores one it meets, as
    safety measures beyond the app's own behaviour; both read the cards
    first, see their docstrings.

    Not tested: 8-byte card ids (including 10-digit numbers above
    4294967295), other lock models, and whether a start date already in
    the past is stored (the listing shows it as "not set").
    """

    def __init__(self, channel: AdminChannel, weekly_schedules: WeeklyScheduleManager) -> None:
        """Bind the manager to the client's admin channel and its weekly-window manager."""
        self._channel = channel
        self._weekly_schedules = weekly_schedules

    async def list(self, *, include_weekly_windows: bool = True) -> list[CardEntry]:
        """Read every enrolled card, with its weekly windows unless told not to.

        One round trip per card, following the lock's own list cursor: the
        first query sends position 0 and each reply's position is sent back
        as the next query, so the lock answers with the next card after it.
        Positions skip deleted cards - counting 0, 1, 2, ... would list the
        card after a gap twice (confirmed on SN484_PV53). Stops at the
        lock's end-of-list reply, or when a reply's position does not
        advance (a repeat of a card already listed); raises `TTLockError`
        if neither happens within `_MAX_CARD_ENTRIES` queries. Not gated
        on a feature, so it keeps working on locks whose mask omits `IC`.

        With `include_weekly_windows` each entry's `weekly_windows` holds
        what `WeeklyScheduleManager.get` reads. A card without windows gets
        no reply to that query, so each one costs a short timeout and a
        reconnect: pass `False` for a fast listing, which leaves
        `weekly_windows` as `None` ("not read") - a card listed that way
        may still be restricted. On a lock without
        `CYCLIC_IC_OR_FINGER_PRINT` no card can have windows, so none are
        read and every entry gets an empty tuple.
        """
        async with self._channel.session():
            entries = await self._read_entries()
        log.info("fetched %d card(s)", len(entries))
        if include_weekly_windows:
            return [*await self._with_weekly_windows(entries)]
        return [*entries]

    async def _read_entries(self) -> Sequence[CardEntry]:
        """Follow the lock's list cursor inside the caller's session; see `list`."""
        entries: list[CardEntry] = []
        position = 0
        for _ in range(_MAX_CARD_ENTRIES):
            plain = await self._channel.query(
                cmd.CMD_MANAGE_IC_CARD, cmd.payload_card_list(position), "get_cards"
            )
            log.debug("card list response: length=%d", len(plain))
            try:
                page = cmd.parse_card_list_page(plain)
            except (RuntimeError, ValueError) as error:
                raise TTLockError(f"Failed to get_cards: {error}") from None
            if page is None:
                return entries
            entry, reply_position = page
            if reply_position <= position:
                return entries
            entries.append(entry)
            position = reply_position
        raise TTLockError(
            f"Failed to get_cards: exceeded safety cap of "
            f"{_MAX_CARD_ENTRIES} entries without an end-of-list response"
        )

    async def enroll(
        self,
        validity: Validity | None = None,
        on_progress: ProgressCallback | None = None,
        *,
        timeout: float = DEFAULT_ENROLL_TIMEOUT,  # noqa: ASYNC109 -- the lock's silence is the answer, so the deadline is part of the call
    ) -> Credential:
        """Enroll the card someone taps on the lock, permanent unless `validity` says otherwise.

        Puts the lock in add mode and waits for a tap. `on_progress` is
        called with `CardEnrollmentStep.WAITING_FOR_CARD` when the lock
        asks for the card - the moment to tell the person to present it -
        and with `CARD_READ` once it was enrolled and its validity applied;
        it must not block.
        Returns the new card's `Credential`, which the other methods take;
        its `card_number` is the number printed on the card's listing.

        `timeout` is how long to wait for the card (captures show a tap 3.5
        to 7 seconds after the command). The lock sends nothing when its own
        wait ends, and it may stay in add mode for a while after the caller
        gave up: on an SN484_PV53 lock a card presented 10 s after the
        command was enrolled as a permanent one, while one at 20 s was
        rejected (other models: not tested, and the SDK has no command to
        leave add mode). So the call keeps listening until
        `ENROLL_SAFETY_WINDOW` (30 s) has passed since the command, even when
        `timeout` is shorter, and a `timeout` below it only changes what a
        late card means:

        - no card at all: `EnrollmentTimeoutError`, after that window;
        - a card after `timeout` but inside the window: it is deleted at
          once and `CardPresentedLateError` says so, and whether the delete
          worked. Do not call that a success.

        An SN534 lock (firmware 6.5.20) drops the BLE link about 21 s into
        an unanswered enrollment, most likely as it leaves add mode, and
        nothing it does in that gap can be heard. So a drop after the lock
        asked for the card ends the wait: once the window has passed, the
        link is reopened and the cards are read again at once, and any card
        that was not there before is deleted and reported with
        `CardPresentedLateError`; with none, `EnrollmentTimeoutError`. The
        client is connected afterwards, unless that check failed, which
        `EnrollmentTimeoutError` reports. `disconnected_callback` fires for
        the drop but not for the reopened link.

        A permanent card needs nothing more. Otherwise its validity is
        applied right after the tap, as the official app does: `Period` and
        `Weekly` send their dates (an unbounded `Weekly` sends those of a
        permanent card), and `Weekly` then writes its windows with
        `WeeklyScheduleManager.set`. If either step fails, the card would
        stay permanent and unrestricted, so it is deleted again and a
        `TTLockError` reports the original failure and whether the delete
        worked - never retried silently. Another command from the same
        client may run between the steps. A cancelled call is not rolled
        back: list the cards afterwards.

        Tapping a card the lock already holds is reported exactly like a new
        enrollment, and the lock resets it: its dates become permanent and
        its weekly windows are wiped (SN484_PV53). The official app does not
        notice this - it reports success and the card loses its dates and
        windows. So the cards, with their windows, are read before add mode
        starts (`list`: a card without windows costs a short timeout and a
        reconnect each, before the lock is asked for anything). A card found
        in that list is never deleted, on any path: its previous dates and
        windows are written back with `modify` and `CardAlreadyEnrolledError`
        is raised, with `restored` telling whether that worked - when it did
        not, the card may now be permanent and unrestricted. This restore is
        a safety addition beyond what the app does. Only a card that was not
        in the list is deleted, by a rollback or as a late card.

        Raises `StorageFullError` when the lock has no room left.
        """
        validity = validity or Permanent()
        cmd.check_card_validity(validity)
        held = {entry.card_id: entry for entry in await self.list()}
        failure: TTLockError | None = None
        try:
            async with self._channel.session():
                await self._require_cards("enroll_card", validity)
                credential, late = await self._wait_for_card(on_progress, timeout)
                previous = held.get(credential.identifier)
                if previous is None and late:
                    raise await self._remove_late_card(credential, timeout)
                if previous is None and not isinstance(validity, Permanent):
                    failure = await self._try(
                        self._apply_dates(credential, validity, "enroll_card")
                    )
        except _LinkDroppedInAddMode as dropped:
            raise await self._check_after_link_drop(held, dropped.started, timeout) from (
                dropped.__cause__
            )
        if previous is not None:
            raise await self._restore(credential, previous, late=late)
        if failure is None and isinstance(validity, Weekly):
            failure = await self._try(self._weekly_schedules.set(credential, validity.windows))
        if failure is not None:
            raise await self._roll_back(credential, failure, "enroll_card")
        if on_progress is not None:
            on_progress(CardEnrollmentStep.CARD_READ)
        return credential

    async def _wait_for_card(
        self,
        on_progress: ProgressCallback | None,
        timeout: float,  # noqa: ASYNC109 -- forwarded to the channel, which owns the deadline
    ) -> tuple[Credential, bool]:
        """Enter add mode inside the caller's session; return the card read and whether it was late.

        Listens for `ENROLL_SAFETY_WINDOW` at least, so a card tapped after
        `timeout` is still seen; it is "late" when it arrived after `timeout`.
        """
        waiting = False
        late = False
        card_id = b""
        started = time.monotonic()

        def on_reply(data: bytes) -> bool:
            nonlocal waiting, card_id, late
            try:
                read = cmd.parse_card_enrollment_reply(data)
            except ValueError as error:
                raise TTLockError(f"Failed to enroll_card: {error}") from None
            if read is not None:
                card_id = read
                late = time.monotonic() - started > timeout
                return True
            waiting = True
            if on_progress is not None:
                on_progress(CardEnrollmentStep.WAITING_FOR_CARD)
            return False

        try:
            await self._channel.command(
                cmd.CMD_MANAGE_IC_CARD,
                cmd.payload_card_enroll(),
                "enroll_card",
                on_reply=on_reply,
                timeout=max(timeout, ENROLL_SAFETY_WINDOW),
            )
        except LinkLostError as error:
            if not waiting:
                raise
            log.info("lock dropped the link in add mode")
            raise _LinkDroppedInAddMode(started) from error
        except ReplyTimeoutError as error:
            if not waiting:
                raise
            raise EnrollmentTimeoutError(
                f"Failed to enroll_card: no card was presented within {timeout:g} s, "
                f"nor during the {ENROLL_SAFETY_WINDOW:g} s the lock may still listen"
            ) from error
        log.info("card enrolled")
        return Credential(CredentialType.CARD, card_id), late

    async def _restore(
        self, credential: Credential, previous: CardEntry, *, late: bool
    ) -> CardAlreadyEnrolledError:
        """Write a re-enrolled card's previous dates and windows back and describe the outcome."""
        when = "after the timeout " if late else ""
        try:
            await self.modify(credential, _validity_of(previous))
        except (TTLockError, ValueError) as error:
            log.warning("re-enrolled card could not be restored")
            return CardAlreadyEnrolledError(
                "enroll_card",
                f"Failed to enroll_card: a card the lock already held was presented {when}and "
                f"the lock reset it, and restoring its previous validity failed ({error}); it may "
                "now be permanent and unrestricted - list the cards and fix it with modify",
                restored=False,
            )
        log.warning("re-enrolled card restored")
        return CardAlreadyEnrolledError(
            "enroll_card",
            f"Failed to enroll_card: a card the lock already held was presented {when}and the "
            "lock reset it; its previous dates and weekly windows were restored",
            restored=True,
        )

    async def _check_after_link_drop(
        self,
        held: dict[bytes, CardEntry],
        started: float,
        timeout: float,  # noqa: ASYNC109 -- only reported
    ) -> TTLockError:
        """Reconnect, then find and delete any card enrolled while the link was down.

        Waits until `ENROLL_SAFETY_WINDOW` has passed since the command before
        reconnecting, so the lock has left add mode, and then reads the cards
        on the new link straight away: the lock drops a link that stays idle
        for a few seconds.
        """
        remaining = started + ENROLL_SAFETY_WINDOW - time.monotonic()
        if remaining > 0:
            await asyncio.sleep(remaining)
        removed = True
        try:
            async with self._channel.reopened_session():
                listed = await self._read_entries()
                arrived = [entry.card_id for entry in listed if entry.card_id not in held]
                for card_id in arrived:
                    try:
                        await self._channel.command(
                            cmd.CMD_MANAGE_IC_CARD, cmd.payload_card_delete(card_id), "delete_card"
                        )
                    except LockRejectedError:
                        removed = False
        except TTLockError as error:
            return EnrollmentTimeoutError(
                "Failed to enroll_card: the lock dropped the link while waiting for a card, and "
                f"checking the cards afterwards failed ({error}); a card presented meanwhile may "
                "have been enrolled as permanent - reconnect and list the cards"
            )
        if not arrived:
            return EnrollmentTimeoutError(
                f"Failed to enroll_card: no card was presented within {timeout:g} s; the lock "
                "dropped the link when it left add mode"
            )
        if not removed:
            log.warning("card enrolled while the link was down could not be removed")
            return CardPresentedLateError(
                "Failed to enroll_card: a card was enrolled as permanent while the lock had "
                "dropped the link, and deleting it failed; it may still open the lock - list "
                "the cards and delete it",
                removed=False,
            )
        log.warning("card enrolled while the link was down removed")
        return CardPresentedLateError(
            "Failed to enroll_card: a card was enrolled while the lock had dropped the link, "
            "and was removed again",
            removed=True,
        )

    async def _remove_late_card(self, credential: Credential, timeout: float) -> TTLockError:  # noqa: ASYNC109 -- only reported
        """Delete a card enrolled after the timeout, in the caller's session, and describe it."""
        try:
            await self._channel.command(
                cmd.CMD_MANAGE_IC_CARD,
                cmd.payload_card_delete(credential.identifier),
                "delete_card",
            )
        except TTLockError as error:
            log.warning("late card could not be removed")
            return CardPresentedLateError(
                f"Failed to enroll_card: a card was presented after the {timeout:g} s timeout and "
                f"enrolled as permanent, and deleting it failed ({error}); it may still open the "
                "lock - list the cards and delete it",
                removed=False,
            )
        log.warning("late card removed")
        return CardPresentedLateError(
            f"Failed to enroll_card: a card was presented after the {timeout:g} s timeout and "
            "was removed again",
            removed=True,
        )

    async def add(self, card: Credential, validity: Validity | None = None) -> None:
        """Add a card by its id, without tapping it; permanent unless `validity` says otherwise.

        `card` is `Credential.card(number)`: 4 bytes, or 8 above
        0xFFFFFFFF. The SDK instead switches at 10 decimal digits, so a
        10-digit number above 4294967295 may be addressed differently by
        the lock (not tested, like every 8-byte id). Confirmed on an
        SN484_PV53 lock for a permanent card, which the lock accepts.
        `Permanent` sends the dates the lock lists for a permanent card
        (the SDK's own default is about 2000-02-01 to 2099-12-01).

        The lock answers adding a card it already holds with success and
        replaces that card's dates (SN484_PV53: a card limited to ten days
        became permanent). So the cards are read first, without windows,
        and a card already held raises `CardAlreadyEnrolledError` - a
        `CredentialAlreadyExistsError` - pointing to `modify`, with nothing
        sent. Only a card that was absent can be deleted by the rollback
        below.

        A `Weekly` validity writes its windows after the card is added; if
        that fails the card is deleted again, as in `enroll`.

        Raises `ValueError` for a credential that is not a card, and
        `StorageFullError` when the lock has no room left.
        """
        validity = validity or Permanent()
        identifier = _card_id(card)
        payload = cmd.payload_card_add(identifier, validity)
        if any(
            entry.card_id == identifier for entry in await self.list(include_weekly_windows=False)
        ):
            raise CardAlreadyEnrolledError(
                "add_card",
                "Failed to add_card: the lock already holds this card; adding it again would "
                "replace its dates - use modify to change its validity",
            )
        async with self._channel.session():
            await self._require_cards("add_card", validity)
            await self._channel.command(cmd.CMD_MANAGE_IC_CARD, payload, "add_card")
        if isinstance(validity, Weekly):
            failure = await self._try(self._weekly_schedules.set(card, validity.windows))
            if failure is not None:
                raise await self._roll_back(card, failure, "add_card")

    async def modify(self, card: Credential, validity: Validity) -> None:
        """Change a card's validity, replacing its dates and its weekly windows.

        `Period` sets its dates. `Weekly` sets its dates (an unbounded one
        those of a permanent card) and then its windows. `Permanent` sends
        the dates the lock lists for a permanent card, 2000-01-01 00:00 to
        2099-01-01 00:00; confirmed on an SN484_PV53 lock, which lists the
        card as permanent and accepts it. Any validity but `Weekly` also
        clears the card's windows, which is not an error when it has none.
        A start date in the future is enforced: after the card was modified
        to a period starting the next day, the lock accepted the change and
        rejected the card when it was presented (SN484_PV53).
        Whether a start date already in the past is stored is not tested
        (the listing shows it as "not set").

        If writing the windows fails after the dates were changed, the
        dates stay changed and the card may have fewer windows than asked
        (see `WeeklyScheduleManager.set`); read it back with `list`.

        Raises `ValueError` for a credential that is not a card, and
        `CredentialNotFoundError` if the lock does not hold the card.
        """
        payload = cmd.payload_card_modify(_card_id(card), validity)
        async with self._channel.session():
            await self._require_cards("modify_card", validity)
            await self._channel.command(cmd.CMD_MANAGE_IC_CARD, payload, "modify_card")
        if isinstance(validity, Weekly):
            await self._weekly_schedules.set(card, validity.windows)
            return
        try:
            await self._weekly_schedules.clear(card)
        except UnsupportedFeatureError:
            log.debug("lock has no weekly windows to clear")

    async def delete(self, card: Credential) -> None:
        """Remove one card.

        Raises `ValueError` for a credential that is not a card, and
        `CredentialNotFoundError` if the lock does not hold it. Its weekly
        windows go with it; not tested.
        """
        payload = cmd.payload_card_delete(_card_id(card))
        async with self._channel.session():
            await self._channel.require("delete_card", LockFeature.IC)
            await self._channel.command(cmd.CMD_MANAGE_IC_CARD, payload, "delete_card")

    async def clear(self) -> None:
        """Remove EVERY card from the lock. There is no undo."""
        async with self._channel.session():
            await self._channel.require("clear_cards", LockFeature.IC)
            await self._channel.command(
                cmd.CMD_MANAGE_IC_CARD, cmd.payload_card_clear(), "clear_cards"
            )

    async def _require_cards(self, action: str, validity: Validity) -> None:
        await self._channel.require(action, LockFeature.IC)
        if isinstance(validity, Weekly):
            await self._channel.require(action, LockFeature.CYCLIC_IC_OR_FINGER_PRINT)

    async def _apply_dates(self, credential: Credential, validity: Validity, action: str) -> None:
        payload = cmd.payload_card_modify(credential.identifier, validity)
        await self._channel.command(cmd.CMD_MANAGE_IC_CARD, payload, action)

    async def _with_weekly_windows(self, entries: Sequence[CardEntry]) -> tuple[CardEntry, ...]:
        with_windows: tuple[CardEntry, ...] = ()
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
        """Delete a card whose validity could not be applied and describe both outcomes."""
        try:
            async with self._channel.session():
                await self._channel.command(
                    cmd.CMD_MANAGE_IC_CARD,
                    cmd.payload_card_delete(credential.identifier),
                    "delete_card",
                )
        except TTLockError as error:
            log.warning("card rollback failed")
            outcome = (
                f"deleting the new card also failed ({error}); it may remain enrolled "
                "as a permanent, unrestricted card - list the cards and delete it"
            )
        else:
            log.warning("card rolled back")
            outcome = "the new card was deleted again"
        wrapped = TTLockError(f"Failed to {action}: {failure}; {outcome}")
        wrapped.__cause__ = failure
        return wrapped


def _card_id(card: Credential) -> bytes:
    if card.credential_type != CredentialType.CARD:
        raise ValueError("expected a card credential")
    return card.identifier


def _validity_of(entry: CardEntry) -> Validity:
    """Return the validity a listed card has, from its dates and weekly windows."""
    windows = entry.weekly_windows or ()
    if entry.start_date is None and entry.end_date is None:
        return Weekly(windows) if windows else Permanent()
    start = entry.start_date or dt.datetime(2000, 1, 1)  # noqa: DTZ001 -- lock RTC is naive
    end = entry.end_date or dt.datetime(2099, 1, 1)  # noqa: DTZ001 -- lock RTC is naive
    return Weekly(windows, start, end) if windows else Period(start, end)
