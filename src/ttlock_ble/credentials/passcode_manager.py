"""PasscodeManager: list, add, change and remove keypad passcodes."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .. import commands as cmd
from ..constants import KeyboardPwdType, LockFeature
from ..exceptions import TTLockError
from ..models import Permanent, Weekly

if TYPE_CHECKING:
    from ..models import PasscodeEntry, Period, SingleUse, Validity
    from .admin_channel import AdminChannel

log: logging.Logger = logging.getLogger("ttlock_ble.credentials")

# TTLock firmware holds at most 150 passcodes; only a runaway cursor gets here.
_MAX_PASSCODE_ENTRIES = 300


class PasscodeManager:
    """Keypad passcodes on one lock, reached as `TTLockClient.passcodes`.

    Every method is admin-gated and validates its input before touching
    the BLE link. Passcode values never reach logs or exception messages.

    If a passcode shares a digit prefix with another one (`1234` and
    `12345`), the keypad may match the shorter one first whichever was
    typed - firmware behaviour, confirmed through the official app too.
    """

    def __init__(self, channel: AdminChannel) -> None:
        """Bind the manager to the client's admin channel."""
        self._channel = channel

    async def list(self) -> list[PasscodeEntry]:
        """Read the passcodes this query reports - NOT every passcode on the lock.

        Passcodes created over BLE (by this library or otherwise) appear at
        once. Ones the official app generates offline (CMD 0x31) appear
        only after their first use at the keypad.

        One round trip per entry, following the lock's own cursor until it
        reaches 0. Raises `TTLockError` if the cursor never gets there
        within `_MAX_PASSCODE_ENTRIES` round trips.
        """
        entries: list[PasscodeEntry] = []
        async with self._channel.session():
            sequence = 0
            for _attempt in range(_MAX_PASSCODE_ENTRIES):
                plain = await self._channel.query(
                    cmd.CMD_GET_PASSCODES, cmd.payload_passcode_list(sequence), "get_passcodes"
                )
                log.debug("passcode list response: length=%d", len(plain))
                try:
                    entry, next_sequence = cmd.parse_passcode_list_response(plain)
                except (RuntimeError, ValueError) as error:
                    raise TTLockError(f"Failed to get_passcodes: {error}") from None
                if entry is not None:
                    entries.append(entry)
                if next_sequence == 0:
                    break
                sequence = next_sequence
            else:
                raise TTLockError(
                    f"Failed to get_passcodes: exceeded safety cap of "
                    f"{_MAX_PASSCODE_ENTRIES} entries without the lock's cursor reaching 0"
                )
        log.info("fetched %d passcode(s)", len(entries))
        return entries

    async def add(self, code: str, validity: Validity | None = None) -> None:
        """Create a passcode, permanent unless `validity` says otherwise.

        `Period` and `SingleUse` codes work between their dates; the lock
        reports their start as 2000-01-01 when listed, whatever was sent.
        A `Weekly` code repeats one window on one weekday, Monday to
        Friday, the weekend or every day, for whole hours and with no date
        range, and needs `CYCLIC_PASSCODE_CAN_RECOVERY`; any other schedule
        raises `ValueError` before connecting.

        Raises `CredentialAlreadyExistsError` if the lock already holds
        `code`, and `StorageFullError` when it has no room left.
        """
        validity = validity or Permanent()
        if isinstance(validity, Weekly):
            payload = cmd.payload_passcode_recover_weekly(code, validity)
        else:
            payload = cmd.payload_passcode_create(code, validity)
        async with self._channel.session():
            if isinstance(validity, Weekly):
                await self._channel.require(
                    "add_passcode", LockFeature.CYCLIC_PASSCODE_CAN_RECOVERY
                )
            await self._channel.command(cmd.CMD_MANAGE_KEYBOARD_PASSWORD, payload, "add_passcode")

    async def modify(
        self,
        code: str,
        *,
        new_code: str | None = None,
        validity: Period | SingleUse | None = None,
    ) -> None:
        """Change a passcode's digits, its dates, or both, keeping its type.

        Only the dates of `validity` are used: the lock never turns a
        permanent passcode into a dated one or back - delete and add it
        instead. On a permanent passcode the lock accepts new dates and
        ignores them. Needs `MODIFY_PASSCODE_FUNCTION`.

        Raises `CredentialNotFoundError` if the lock does not hold `code`,
        and `CredentialAlreadyExistsError` if `new_code` is already taken.
        """
        payload = cmd.payload_passcode_modify(code, new_code=new_code, validity=validity)
        async with self._channel.session():
            await self._channel.require("modify_passcode", LockFeature.MODIFY_PASSCODE_FUNCTION)
            await self._channel.command(
                cmd.CMD_MANAGE_KEYBOARD_PASSWORD, payload, "modify_passcode"
            )

    async def delete(self, code: str) -> None:
        """Remove a passcode, whatever its type.

        The lock answers success even when it does not hold `code`, so this
        cannot tell a removal from a no-op; `list` can, for codes it
        reports. A shorter passcode that prefixes `code` keeps working.
        """
        payload = cmd.payload_passcode_delete(KeyboardPwdType.PERMANENT, code)
        async with self._channel.session():
            await self._channel.command(
                cmd.CMD_MANAGE_KEYBOARD_PASSWORD, payload, "delete_passcode"
            )

    async def clear(self) -> None:
        """Remove every keypad passcode from the lock. There is no undo."""
        async with self._channel.session():
            await self._channel.command(
                cmd.CMD_MANAGE_KEYBOARD_PASSWORD, cmd.payload_passcode_clear(), "clear_passcodes"
            )
