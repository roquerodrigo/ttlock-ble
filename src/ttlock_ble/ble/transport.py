"""BleTransport: the BLE link under `TTLockClient` — connection and framing."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

from ..exceptions import TTLockError
from ..protocol import FrameReassembler
from .constants import (
    BATTERY_CHAR,
    BLE_WRITE_CHUNK,
    BONG_NOTIFY,
    BONG_SERVICE,
    BONG_WRITE,
    CONNECT_RETRIES,
    DEFAULT_RECV_TIMEOUT,
    POST_NOTIFY_SETTLE,
    TTL_NOTIFY,
    TTL_SERVICE,
    TTL_WRITE,
)
from .device_finder import find_lock_device

if TYPE_CHECKING:
    from collections.abc import Callable

    from bleak import BleakClient
    from bleak.backends.characteristic import BleakGATTCharacteristic
    from bleak.backends.device import BLEDevice

    from ..protocol import Frame

    DisconnectedCallback = Callable[[BleakClient], None]
    PushFrameHandler = Callable[[Frame], None]
    ResponsePredicate = Callable[[Frame, int], bool]

# The BLE layer keeps logging under `ttlock_ble.client`: the logger name is
# what downstream users scope log levels with, and splitting the module out
# must not silently move their filters.
log: logging.Logger = logging.getLogger("ttlock_ble.client")


class BleTransport:
    """Owns the BLE link to one lock: connection, characteristics, framing.

    The transport knows nothing about the lock's command set. It hands
    every frame it cannot attribute to the exchange in flight to
    `on_push_frame`, and asks `is_response` — both supplied by
    `TTLockClient`, which owns the AES key needed to tell them apart.
    """

    def __init__(  # noqa: PLR0913 -- collaborators and link tuning arrive separately
        self,
        *,
        address: str,
        display_name: str,
        on_push_frame: PushFrameHandler,
        is_response: ResponsePredicate,
        device: BLEDevice | None = None,
        scan_timeout: float = 25.0,
        disconnected_callback: DisconnectedCallback | None = None,
    ) -> None:
        """Configure the link; no BLE I/O happens until `connect()`."""
        self.address = address
        self.display_name = display_name
        self.device = device
        self.scan_timeout = scan_timeout
        self.disconnected_callback = disconnected_callback
        self._on_push_frame = on_push_frame
        self._is_response = is_response
        self._client: BleakClient | None = None
        self._write_char: BleakGATTCharacteristic | None = None
        self._notify_char: BleakGATTCharacteristic | None = None
        self._reassembler = FrameReassembler()
        self._inbox: asyncio.Queue[Frame] = asyncio.Queue()
        self._waiting_for_response = 0

    @property
    def is_connected(self) -> bool:
        """True iff a BLE connection is currently open."""
        return self._client is not None and self._client.is_connected

    async def connect(self) -> None:
        """Resolve the BLE device (if not supplied), GATT-connect, start notify.

        Uses `bleak_retry_connector.establish_connection` so the connection
        cooperates with other integrations sharing the BLE adapter and
        survives transient failures (essential under Home Assistant and
        ESPHome BLE proxies).
        """
        if self.is_connected:
            return
        if self.device is None:
            self.device = await find_lock_device(self.address, self.scan_timeout)
        if self.device is None:
            raise TTLockError(
                f"Failed to find lock {self.address} via BLE scan: "
                "wake the lock by touching the keypad and try again"
            )
        try:
            self._client = await establish_connection(
                BleakClientWithServiceCache,
                self.device,
                self.display_name,
                disconnected_callback=self.disconnected_callback,
                use_services_cache=True,
                max_attempts=CONNECT_RETRIES,
            )
        except Exception as exc:
            raise TTLockError(f"Failed to connect to lock over BLE: {exc}") from exc
        await self._discover_chars()
        assert self._notify_char is not None
        await self._client.start_notify(self._notify_char, self._on_notify)
        await asyncio.sleep(POST_NOTIFY_SETTLE)
        await self._wake_battery_read()
        log.info("Connected to %s (%s)", self.display_name, self.address)

    async def disconnect(self) -> None:
        """Stop notifications and tear down the BLE connection."""
        if self._client is not None and self._client.is_connected:
            try:
                if self._notify_char is not None:
                    await self._client.stop_notify(self._notify_char)
            except Exception:  # teardown swallows whatever bleak raises
                log.debug("stop_notify failed; ignoring on teardown", exc_info=True)
            await self._client.disconnect()
        self._client = None

    async def exchange(self, frame: Frame, *, timeout: float = DEFAULT_RECV_TIMEOUT) -> Frame:  # noqa: ASYNC109 -- the deadline is the whole point of this helper
        """Send `frame` and return the lock's reply to *that* command.

        The lock pushes unsolicited frames on the same characteristic,
        and one landing inside this window used to be handed back as the
        response: the parsers do not check the echoed opcode, so a
        15-byte log push read as a status reply yields whatever its
        second byte happens to be — for a manual key that is the uid's
        high byte, zero, decoding as LOCKED while the door is open. It
        also left the real reply in the inbox, desynchronising every
        later exchange by one frame.

        Frames `is_response` rejects are therefore routed to the push
        handler, where they belong, and the wait continues on the
        original deadline rather than restarting.
        """
        # Inbox-vs-push routing in `_on_notify` keys off this flag, so
        # increment around the entire send-then-receive window.
        self._waiting_for_response += 1
        try:
            await self.send(frame)
            loop = asyncio.get_running_loop()
            deadline = loop.time() + timeout
            msg = f"Timed out waiting {timeout:.1f}s for the lock to reply"
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise TTLockError(msg)
                try:
                    candidate = await asyncio.wait_for(self._inbox.get(), timeout=remaining)
                except TimeoutError as exc:
                    raise TTLockError(msg) from exc
                if self._is_response(candidate, frame.command):
                    return candidate
                log.debug(
                    "Push frame arrived while awaiting 0x%02x; dispatching it",
                    frame.command,
                )
                self._on_push_frame(candidate)
        finally:
            self._waiting_for_response -= 1

    async def send(self, frame: Frame) -> None:
        """Write one frame to the lock, chunked to the ATT payload limit."""
        assert self._client is not None
        assert self._write_char is not None
        wire = frame.build()
        log.debug("TX %s (%d bytes)", wire.hex(), len(wire))
        for i in range(0, len(wire), BLE_WRITE_CHUNK):
            await self._client.write_gatt_char(
                self._write_char,
                wire[i : i + BLE_WRITE_CHUNK],
                response=False,
            )

    async def _discover_chars(self) -> None:
        """Pick the GATT service+chars used by the firmware on this lock."""
        assert self._client is not None
        services = self._client.services
        for svc_uuid, w_uuid, n_uuid in (
            (TTL_SERVICE, TTL_WRITE, TTL_NOTIFY),
            (BONG_SERVICE, BONG_WRITE, BONG_NOTIFY),
        ):
            svc = services.get_service(svc_uuid)
            if svc is None:
                continue
            write_char = svc.get_characteristic(w_uuid)
            notify_char = svc.get_characteristic(n_uuid)
            if write_char is not None and notify_char is not None:
                self._write_char = write_char
                self._notify_char = notify_char
                log.info("Using GATT service %s", svc_uuid)
                return
        raise TTLockError(
            "Failed to discover TTLock GATT service: lock exposed neither "
            f"{TTL_SERVICE} nor {BONG_SERVICE}"
        )

    async def _wake_battery_read(self) -> None:
        """Read the standard battery characteristic to nudge the BLE stack awake.

        Some firmware revisions only enable the notify pipeline after the
        central has issued at least one ATT read. The reported value is
        unreliable on this firmware (always 100%); the in-band protocol
        value from `query_state()` is used instead.
        """
        assert self._client is not None
        try:
            data = await self._client.read_gatt_char(BATTERY_CHAR)
            log.debug("Wake-up battery read: %d", data[0] if data else -1)
        except Exception:  # non-critical wake nudge
            log.debug("Battery read skipped", exc_info=True)

    def _on_notify(self, _char: BleakGATTCharacteristic, data: bytearray) -> None:
        log.debug("RX %s", bytes(data).hex())
        for frame in self._reassembler.feed(bytes(data)):
            if self._waiting_for_response > 0:
                self._inbox.put_nowait(frame)
            else:
                self._on_push_frame(frame)
