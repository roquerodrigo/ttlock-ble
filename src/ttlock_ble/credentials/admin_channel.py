"""AdminChannel: the slice of `TTLockClient` the credential managers are allowed to use."""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

from ..ble.constants import DEFAULT_RECV_TIMEOUT

if TYPE_CHECKING:
    import asyncio
    from collections.abc import AsyncIterator, Awaitable, Callable
    from typing import Protocol

    from ..constants import LockFeature

    ReplyHandler = Callable[[bytes], bool]
    QuerySender = Callable[[int, bytes, str], Awaitable[bytes]]
    FeatureCheck = Callable[[str, LockFeature], Awaitable[None]]
    Authorizer = Callable[[], Awaitable[None]]

    class CommandSender(Protocol):
        """`TTLockClient._credential_command`'s shape."""

        def __call__(
            self,
            opcode: int,
            payload: bytes,
            action: str,
            *,
            on_reply: ReplyHandler | None = ...,
            timeout: float = ...,
        ) -> Awaitable[bytes]:
            """Send one credential command and return the final reply's data."""
            ...


class AdminChannel:
    """An admin session on the lock, without the rest of the client.

    `TTLockClient` builds one around its own command lock, admin handshake
    and command helpers, so a manager can run commands and check features
    but cannot reach the transport, the AES key or the event listeners.
    Every call except `session` must run inside `session`.
    """

    def __init__(
        self,
        *,
        command_lock: asyncio.Lock,
        authorize: Authorizer,
        send: CommandSender,
        query: QuerySender,
        require_feature: FeatureCheck,
    ) -> None:
        """Wire the channel to the client's lock and helpers; no BLE I/O happens here."""
        self._command_lock = command_lock
        self._authorize = authorize
        self._send = send
        self._query = query
        self._require_feature = require_feature

    @contextlib.asynccontextmanager
    async def session(self) -> AsyncIterator[None]:
        """Hold the client's command lock and authorize as admin for the block's duration."""
        async with self._command_lock:
            await self._authorize()
            yield

    async def command(
        self,
        opcode: int,
        payload: bytes,
        action: str,
        *,
        on_reply: ReplyHandler | None = None,
        timeout: float = DEFAULT_RECV_TIMEOUT,  # noqa: ASYNC109 -- forwarded to the transport, which owns the deadline
    ) -> bytes:
        """Return the final reply's data of a credential command; refusals raise typed errors."""
        return await self._send(opcode, payload, action, on_reply=on_reply, timeout=timeout)

    async def query(self, opcode: int, payload: bytes, action: str) -> bytes:
        """Send a read command and return the decrypted reply, envelope included, for its parser."""
        return await self._query(opcode, payload, action)

    async def require(self, action: str, feature: LockFeature) -> None:
        """Raise `UnsupportedFeatureError` unless the lock advertises `feature`."""
        await self._require_feature(action, feature)
