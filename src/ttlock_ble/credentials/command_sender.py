"""CommandSender: the shape of the client callable that sends one credential command."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


class CommandSender(Protocol):
    """`TTLockClient._credential_command`'s shape, as `AdminChannel` calls it."""

    def __call__(
        self,
        opcode: int,
        payload: bytes,
        action: str,
        *,
        on_reply: Callable[[bytes], bool] | None = ...,
        timeout: float | None = ...,
    ) -> Awaitable[bytes]:
        """Send one credential command and return the final reply's data."""
        ...
