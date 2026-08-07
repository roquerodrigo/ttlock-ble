"""KeepAlive: holds the BLE link open for a window after a command."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from typing import TYPE_CHECKING

from ..exceptions import TTLockError
from .constants import KEEP_ALIVE_INTERVAL

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    Poke = Callable[[], Awaitable[None]]
    ConnectionProbe = Callable[[], bool]

# The BLE layer keeps logging under `ttlock_ble.client`: the logger name is
# what downstream users scope log levels with, and splitting the module out
# must not silently move their filters.
log: logging.Logger = logging.getLogger("ttlock_ble.client")


class KeepAlive:
    """Periodically pokes the lock so push events keep flowing after a command.

    The lock idles the link out within a few seconds of silence, which
    would cut off keypad / fingerprint / auto-lock notifications right
    after the operation a caller is most interested in. The poke itself
    is injected: which command is cheap enough to send is the client's
    business, not the link's.
    """

    def __init__(
        self,
        *,
        window_seconds: float,
        poke: Poke,
        is_connected: ConnectionProbe,
        lock_label: str,
    ) -> None:
        """Configure the window; nothing runs until `restart()`."""
        self._window_seconds = window_seconds
        self._poke = poke
        self._is_connected = is_connected
        self._lock_label = lock_label
        self._task: asyncio.Task[None] | None = None

    @property
    def task(self) -> asyncio.Task[None] | None:
        """The window currently running, or `None` when idle."""
        return self._task

    def restart(self) -> None:
        """Schedule a fresh keep-alive window. Cancels any prior one."""
        if self._window_seconds <= 0:
            return
        if self._task is not None and not self._task.done():
            self._task.cancel()
        self._task = asyncio.create_task(
            self.run(),
            name=f"ttlock_ble.keepalive.{self._lock_label}",
        )

    async def stop(self) -> None:
        """Cancel the running window, if any."""
        if self._task is None or self._task.done():
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await self._task
        self._task = None

    async def run(self) -> None:
        """Poke the lock every `KEEP_ALIVE_INTERVAL` seconds until the window closes."""
        deadline = time.monotonic() + self._window_seconds
        while time.monotonic() < deadline and self._is_connected():
            await asyncio.sleep(KEEP_ALIVE_INTERVAL)
            if not self._is_connected():
                return
            try:
                await self._poke()
            except TTLockError as exc:
                log.debug("keep-alive poke failed for %s: %s", self._lock_label, exc)
                return
