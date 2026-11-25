"""AdminChannel: the slice of `TTLockClient` the credential managers are allowed to use."""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import asyncio
    from collections.abc import AsyncIterator, Awaitable, Callable

    from ..constants import LockFeature
    from .command_sender import CommandSender
    from .query_sender import QuerySender

    ReplyHandler = Callable[[bytes], bool]
    FeatureCheck = Callable[[str, LockFeature], Awaitable[None]]
    Authorizer = Callable[[], Awaitable[None]]


class AdminChannel:
    """An admin session on the lock, without the rest of the client.

    `TTLockClient` builds one around its own command lock, admin handshake
    and command helpers, so a manager can run commands and check features
    but cannot reach the transport, the AES key or the event listeners.
    Every other call must run inside `session` or `reopened_session`.
    """

    def __init__(  # noqa: PLR0913 -- one collaborator per capability the managers get
        self,
        *,
        command_lock: asyncio.Lock,
        authorize: Authorizer,
        send: CommandSender,
        query: QuerySender,
        require_feature: FeatureCheck,
        reopen: Authorizer,
    ) -> None:
        """Wire the channel to the client's lock and helpers; no BLE I/O happens here."""
        self._command_lock = command_lock
        self._authorize = authorize
        self._send = send
        self._query = query
        self._require_feature = require_feature
        self._reopen = reopen

    @contextlib.asynccontextmanager
    async def session(self) -> AsyncIterator[None]:
        """Hold the client's command lock and authorize as admin for the block's duration."""
        async with self._command_lock:
            await self._authorize()
            yield

    @contextlib.asynccontextmanager
    async def reopened_session(self) -> AsyncIterator[None]:
        """Like `session`, on a fresh link: for a lock that dropped the old one."""
        async with self._command_lock:
            await self._reopen()
            yield

    async def command(
        self,
        opcode: int,
        payload: bytes,
        action: str,
        *,
        on_reply: ReplyHandler | None = None,
        timeout: float | None = None,  # noqa: ASYNC109 -- forwarded to the transport, which owns the deadline
    ) -> bytes:
        """Return the final reply's data of a credential command; refusals raise typed errors.

        `timeout` overrides the client's reply deadline for this command.
        """
        return await self._send(opcode, payload, action, on_reply=on_reply, timeout=timeout)

    async def query(
        self,
        opcode: int,
        payload: bytes,
        action: str,
        *,
        timeout: float | None = None,  # noqa: ASYNC109 -- forwarded to the transport, which owns the deadline
    ) -> bytes:
        """Send a read command and return the decrypted reply, envelope included, for its parser.

        Raises `ReplyTimeoutError` when nothing arrives within `timeout`.
        """
        return await self._query(opcode, payload, action, timeout=timeout)

    async def reopen(self) -> None:
        """Reconnect and authorize again, keeping the session; for a lock that stopped answering."""
        await self._reopen()

    async def require(self, action: str, feature: LockFeature) -> None:
        """Raise `UnsupportedFeatureError` unless the lock advertises `feature`."""
        await self._require_feature(action, feature)
