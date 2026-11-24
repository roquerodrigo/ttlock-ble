"""AdminPasscodeManager: the keypad code that opens the lock's settings."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .. import commands as cmd
from ..constants import LockFeature
from ..exceptions import TTLockError

if TYPE_CHECKING:
    from .admin_channel import AdminChannel


class AdminPasscodeManager:
    """The lock's admin passcode, reached as `TTLockClient.admin_passcode`.

    It unlocks the door and opens the lock's settings menu at the keypad,
    so it is returned only to the caller and never logged.
    """

    def __init__(self, channel: AdminChannel) -> None:
        """Bind the manager to the client's admin channel."""
        self._channel = channel

    async def get(self) -> str:
        """Read the admin passcode; needs `GET_ADMIN_CODE`."""
        async with self._channel.session():
            await self._channel.require("get_admin_passcode", LockFeature.GET_ADMIN_CODE)
            data = await self._channel.command(
                cmd.CMD_GET_ADMIN_PASSCODE, b"", "get_admin_passcode"
            )
        try:
            return cmd.parse_admin_passcode(data)
        except ValueError as error:
            raise TTLockError(f"Failed to get_admin_passcode: {error}") from None

    async def set(self, code: str) -> None:
        """Replace the admin passcode with `code` (4-9 digits)."""
        payload = cmd.payload_set_admin_passcode(code)
        async with self._channel.session():
            await self._channel.command(cmd.CMD_SET_ADMIN_PASSCODE, payload, "set_admin_passcode")
