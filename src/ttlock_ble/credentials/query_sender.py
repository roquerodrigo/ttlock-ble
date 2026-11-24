"""QuerySender: the shape of the client callable that sends one read command."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Awaitable


class QuerySender(Protocol):
    """`TTLockClient._query`'s shape, as `AdminChannel` calls it."""

    def __call__(
        self, opcode: int, payload: bytes, label: str, *, timeout: float | None = ...
    ) -> Awaitable[bytes]:
        """Send one command and return the decrypted reply, envelope included."""
        ...
