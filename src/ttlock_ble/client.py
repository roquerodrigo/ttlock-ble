"""TTLockClient: async BLE client driving an already-paired TTLock-family lock."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from typing import TYPE_CHECKING, Self

from bleak import BleakClient, BleakScanner
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

from . import commands as cmd
from .constants import KeyboardPwdType
from .crypto import aes_decrypt, hex_key_to_bytes
from .exceptions import TTLockError
from .models import LockEvent, LogEntry
from .protocol import Frame, FrameReassembler

if TYPE_CHECKING:
    import datetime as dt
    from collections.abc import Callable

    from bleak.backends.characteristic import BleakGATTCharacteristic
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData

    from .models import VirtualKey

    DisconnectedCallback = Callable[[BleakClient], None]
    EventListener = Callable[[LockEvent], None]

log: logging.Logger = logging.getLogger("ttlock_ble.client")

TTL_SERVICE = "00001910-0000-1000-8000-00805f9b34fb"
TTL_WRITE = "0000fff2-0000-1000-8000-00805f9b34fb"
TTL_NOTIFY = "0000fff4-0000-1000-8000-00805f9b34fb"

BONG_SERVICE = "6e400001-b5a3-f393-e0a9-e50e24dcca1e"
BONG_WRITE = "6e400002-b5a3-f393-e0a9-e50e24dcca1e"
BONG_NOTIFY = "6e400003-b5a3-f393-e0a9-e50e24dcca1e"

SCIENER_SERVICE = "73631912-6965-6e65-7269-736669727374"
SCIENER_CHAR = "73632b12-6965-6e65-7269-736669727374"

BATTERY_CHAR = "00002a19-0000-1000-8000-00805f9b34fb"

_BLE_WRITE_CHUNK = 20
_DEFAULT_RECV_TIMEOUT = 6.0
_CONNECT_RETRIES = 3
_CONNECT_RETRY_DELAY = 1.0
_POST_NOTIFY_SETTLE = 0.5
_DEFAULT_KEEP_ALIVE_SECONDS = 25.0
_KEEP_ALIVE_INTERVAL = 2.0


class TTLockClient:
    """Async BLE client driving a single, already-paired TTLock-family lock.

    Usage:

        async with TTLockClient(virtual_key) as lock:
            await lock.unlock()

    The client picks the right GATT service, runs the CHECK_USER_TIME
    handshake to obtain `psFromLock`, then issues the actual UNLOCK /
    LOCK / state command.
    """

    def __init__(
        self,
        key: VirtualKey,
        *,
        device: BLEDevice | None = None,
        scan_timeout: float = 25.0,
        disconnected_callback: DisconnectedCallback | None = None,
        keep_alive_after_command: float = _DEFAULT_KEEP_ALIVE_SECONDS,
    ) -> None:
        """Configure the client; no BLE I/O happens until `connect()`.

        If `device` is provided (e.g. handed in by Home Assistant's bluetooth
        integration after discovery), `connect()` skips the active scan.
        Otherwise the client scans for `key.lockMac` itself.

        `keep_alive_after_command` (seconds, default 25) keeps the BLE link
        active that long after every `lock()` / `unlock()` so push events
        from the lock (auto-lock fired, keypad / fingerprint operations)
        keep flowing to `add_event_listener` callbacks in real time. Set
        to 0 to disable.
        """
        self.key = key
        self.scan_timeout = scan_timeout
        self._aes_key: bytes = hex_key_to_bytes(key.aesKeyStr)
        self._device: BLEDevice | None = device
        self._disconnected_callback = disconnected_callback
        self._client: BleakClient | None = None
        self._write_char: BleakGATTCharacteristic | None = None
        self._notify_char: BleakGATTCharacteristic | None = None
        self._reassembler = FrameReassembler()
        self._inbox: asyncio.Queue[Frame] = asyncio.Queue()
        self._waiting_for_response = 0
        self._event_listeners: list[EventListener] = []
        self._command_lock = asyncio.Lock()
        self._keep_alive_seconds = keep_alive_after_command
        self._keep_alive_task: asyncio.Task[None] | None = None

    @classmethod
    def from_ble_device(
        cls,
        device: BLEDevice,
        key: VirtualKey,
        *,
        disconnected_callback: DisconnectedCallback | None = None,
        keep_alive_after_command: float = _DEFAULT_KEEP_ALIVE_SECONDS,
    ) -> TTLockClient:
        """Build a client around a `BLEDevice` already resolved by the caller.

        This is the entry point Home Assistant integrations use: HA's
        bluetooth manager owns discovery and hands a `BLEDevice` to each
        integration on demand, so the integration must NOT scan itself.

        See `__init__` for the `keep_alive_after_command` semantics.
        """
        return cls(
            key,
            device=device,
            disconnected_callback=disconnected_callback,
            keep_alive_after_command=keep_alive_after_command,
        )

    @property
    def is_connected(self) -> bool:
        """True iff a BLE connection is currently open."""
        return self._client is not None and self._client.is_connected

    async def __aenter__(self) -> Self:
        """Connect on entry; disconnect on exit."""
        await self.connect()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        """Release the BLE connection on exit, even when the body raised."""
        await self.disconnect()

    async def connect(self) -> None:
        """Resolve the BLE device (if not supplied), GATT-connect, start notify.

        Uses `bleak_retry_connector.establish_connection` so the connection
        cooperates with other integrations sharing the BLE adapter and
        survives transient failures (essential under Home Assistant and
        ESPHome BLE proxies).
        """
        if self.is_connected:
            return
        if self._device is None:
            self._device = await self._find_device()
        if self._device is None:
            raise TTLockError(
                f"Failed to find lock {self.key.lockMac} via BLE scan: "
                "wake the lock by touching the keypad and try again"
            )
        try:
            self._client = await establish_connection(
                BleakClientWithServiceCache,
                self._device,
                self.key.lockAlias or self.key.lockName or self.key.lockMac,
                disconnected_callback=self._disconnected_callback,
                use_services_cache=True,
                max_attempts=_CONNECT_RETRIES,
            )
        except Exception as exc:
            raise TTLockError(f"Failed to connect to lock over BLE: {exc}") from exc
        await self._discover_chars()
        assert self._notify_char is not None
        await self._client.start_notify(self._notify_char, self._on_notify)
        await asyncio.sleep(_POST_NOTIFY_SETTLE)
        await self._wake_battery_read()
        log.info(
            "Connected to %s (%s)",
            self.key.lockAlias or self.key.lockName,
            self.key.lockMac,
        )

    async def disconnect(self) -> None:
        """Stop notifications and tear down the BLE connection."""
        await self._stop_keep_alive()
        if self._client is not None and self._client.is_connected:
            try:
                if self._notify_char is not None:
                    await self._client.stop_notify(self._notify_char)
            except Exception:  # noqa: BLE001  -- teardown swallows whatever bleak raises
                log.debug("stop_notify failed; ignoring on teardown", exc_info=True)
            await self._client.disconnect()
        self._client = None

    async def unlock(self) -> None:
        """Unlock the door (status=SUCCESS or raises).

        Starts the keep-alive window so push events from the lock flow to
        registered listeners for `keep_alive_after_command` seconds.
        """
        async with self._command_lock:
            ps = await self._check_user_time()
            await self._control_lock(cmd.CMD_UNLOCK, ps, "unlock")
        self._restart_keep_alive()

    async def lock(self) -> None:
        """Re-lock the door (keep-alive applies, same as `unlock`)."""
        async with self._command_lock:
            ps = await self._check_user_time()
            await self._control_lock(cmd.CMD_LOCK, ps, "lock")
        self._restart_keep_alive()

    async def calibrate_time(self, when: dt.datetime | None = None) -> None:
        """Push the current wall-clock time to the lock's RTC.

        TTLock locks keep their own clock that drifts (no NTP, no
        gateway). Time-windowed keys, schedules, and unlock-log
        timestamps all rely on it being accurate. HA integrations
        typically call this once on connect and then daily.
        """
        async with self._command_lock:
            frame = Frame.for_lock(
                self.key.lockVersion,
                cmd.CMD_TIME_CALIBRATE,
                cmd.payload_time_calibrate(when),
            ).encrypt_data(self._aes_key)
            resp = await self._exchange(frame)
            plain = aes_decrypt(resp.data, self._aes_key)
            echo, status, data = cmd.parse_response_status(plain)
            log.info(
                "calibrate_time response: cmd_echo=0x%02x status=%d data=%s",
                echo,
                status,
                data.hex(),
            )
            if status != cmd.RESPONSE_SUCCESS:
                raise TTLockError(
                    f"Failed to calibrate lock time: lock rejected with "
                    f"status={status:#x}, error={data.hex()}"
                )

    def add_event_listener(self, listener: EventListener) -> None:
        """Register a callback for unsolicited push notifications.

        The callback is invoked synchronously from the BLE notify thread
        with a `LockEvent` whenever the lock pushes a frame that wasn't
        a response to a command we sent (keypad unlock, fingerprint
        unlock, mechanical key, etc.). Keep listeners cheap and offload
        any work to a queue/task.
        """
        if listener not in self._event_listeners:
            self._event_listeners.append(listener)

    def remove_event_listener(self, listener: EventListener) -> None:
        """Unregister a previously-added listener (no-op if not present)."""
        with contextlib.suppress(ValueError):
            self._event_listeners.remove(listener)

    async def query_state(self) -> tuple[int, int | None]:
        """Return `(lock_state, battery_pct)`.

        `lock_state`: 0=LOCKED, 1=UNLOCKED, -1=UNKNOWN.
        `battery_pct`: 0-100 or None if not reported.

        Doesn't need CHECK_USER_TIME — search-bicycle-status is unauthenticated.
        """
        async with self._command_lock:
            frame = Frame.for_lock(
                self.key.lockVersion,
                cmd.CMD_QUERY_STATE,
                cmd.payload_query_state(),
            ).encrypt_data(self._aes_key)
            resp = await self._exchange(frame)
            plain = aes_decrypt(resp.data, self._aes_key)
            log.debug("state response plaintext: %s", plain.hex())
            return cmd.parse_lock_status(plain), cmd.parse_state_battery(plain)

    async def get_auto_lock_time(self) -> int:
        """Read the auto-lock delay in seconds (0 = disabled, -1 = unknown)."""
        async with self._command_lock:
            seconds, _battery = await self._auto_lock_exchange(cmd.payload_auto_lock_search())
        log.info("auto-lock delay: %ds", seconds)
        return seconds

    async def set_auto_lock_time(self, seconds: int) -> None:
        """Set the auto-lock delay in seconds. `0` disables auto-lock entirely."""
        async with self._command_lock:
            await self._auto_lock_exchange(cmd.payload_auto_lock_set(seconds))
        log.info("auto-lock delay set to %ds", seconds)

    async def add_passcode(
        self,
        code: str,
        *,
        pwd_type: KeyboardPwdType = KeyboardPwdType.PERMANENT,
        start_date: str = "0001311400",
        end_date: str = "9912311400",
    ) -> None:
        """Provision a keypad passcode (4-9 digits).

        `pwd_type=PERMANENT` ignores `end_date`. For time-windowed codes
        (KeyboardPwdType.PERIOD), pass `start_date` / `end_date` as
        `YYMMDDHHmm` strings.
        """
        async with self._command_lock:
            await self._keyboard_password_exchange(
                cmd.payload_passcode_add(int(pwd_type), code, start_date, end_date),
                "add_passcode",
            )

    async def delete_passcode(
        self,
        code: str,
        *,
        pwd_type: KeyboardPwdType = KeyboardPwdType.PERMANENT,
    ) -> None:
        """Remove a single keypad passcode previously installed via `add_passcode`."""
        async with self._command_lock:
            await self._keyboard_password_exchange(
                cmd.payload_passcode_delete(int(pwd_type), code),
                "delete_passcode",
            )

    async def clear_passcodes(self) -> None:
        """Wipe ALL keypad passcodes from the lock. There's no undo."""
        async with self._command_lock:
            await self._keyboard_password_exchange(
                cmd.payload_passcode_clear(),
                "clear_passcodes",
            )

    async def get_operation_log(self, *, max_entries: int | None = None) -> list[LogEntry]:
        """Pull operation-log entries from the lock, newest-first.

        The lock returns one BLE frame per request — typically just a
        single record on this firmware. We walk the log backwards by
        seeding each subsequent call with the smallest sequence we've
        already seen, deduplicating against records we've already
        captured (some firmware revisions ignore our seq hint and just
        keep echoing the most recent entry, in which case we stop).
        """
        async with self._command_lock:
            all_entries: list[LogEntry] = []
            seen: set[int] = set()
            next_seq = 0xFFFF
            while True:
                frame = Frame.for_lock(
                    self.key.lockVersion,
                    cmd.CMD_GET_OPERATE_LOG,
                    cmd.payload_operate_log_request(next_seq),
                ).encrypt_data(self._aes_key)
                resp = await self._exchange(frame)
                plain = aes_decrypt(resp.data, self._aes_key)
                log.debug("operate_log response plaintext: %s", plain.hex())
                page, last_seq = cmd.parse_operate_log_response(plain)
                log.info("Fetched %d log entr(ies), last_sequence=%d", len(page), last_seq)
                new_entries = [
                    e for e in page if isinstance(e, LogEntry) and e.record_number not in seen
                ]
                if not new_entries:
                    break
                for entry in new_entries:
                    seen.add(entry.record_number)
                all_entries.extend(new_entries)
                if max_entries is not None and len(all_entries) >= max_entries:
                    return all_entries[:max_entries]
                min_seq = min(e.record_number for e in new_entries)
                if min_seq <= 0:
                    break
                next_seq = min_seq
            return all_entries

    def _restart_keep_alive(self) -> None:
        """Schedule a fresh keep-alive window. Cancels any prior one."""
        if self._keep_alive_seconds <= 0:
            return
        if self._keep_alive_task is not None and not self._keep_alive_task.done():
            self._keep_alive_task.cancel()
        self._keep_alive_task = asyncio.create_task(
            self._keep_alive_loop(),
            name=f"ttlock_ble.keepalive.{self.key.lockMac}",
        )

    async def _stop_keep_alive(self) -> None:
        """Cancel the keep-alive task (called from `disconnect()`)."""
        if self._keep_alive_task is None or self._keep_alive_task.done():
            return
        self._keep_alive_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await self._keep_alive_task
        self._keep_alive_task = None

    async def _keep_alive_loop(self) -> None:
        """Periodically poke the lock to keep the BLE link alive.

        The lock idles us out within a few seconds of silence. A
        lightweight `query_state` every `_KEEP_ALIVE_INTERVAL` seconds
        prevents that drop, so push notifications keep flowing to
        registered event listeners for the whole window.
        """
        deadline = time.monotonic() + self._keep_alive_seconds
        while time.monotonic() < deadline and self.is_connected:
            await asyncio.sleep(_KEEP_ALIVE_INTERVAL)
            if not self.is_connected:
                return  # type: ignore[unreachable]
            try:
                async with self._command_lock:
                    frame = Frame.for_lock(
                        self.key.lockVersion,
                        cmd.CMD_QUERY_STATE,
                        cmd.payload_query_state(),
                    ).encrypt_data(self._aes_key)
                    await self._exchange(frame)
            except TTLockError as exc:
                log.debug("keep-alive query failed for %s: %s", self.key.lockMac, exc)
                return

    async def _find_device(self) -> BLEDevice | None:
        """Locate the lock in a way that works on macOS (which hides MACs).

        Match priority:
          1. exact MAC (works on Linux/Windows), then
          2. the last 3 octets of the MAC appearing as a hex suffix in the
             device's advertised name (`S534_1d22bd` for `…22:1D`).

        Falls back to `None` rather than connecting to a neighbour's lock.
        """
        target = self.key.lockMac.upper()
        suffix_bytes = bytes.fromhex(target.replace(":", ""))[-3:][::-1].hex()
        log.info(
            "Scanning %.0fs for %s (MAC suffix '%s')…",
            self.scan_timeout,
            target,
            suffix_bytes,
        )
        match: list[BLEDevice] = []
        loop = asyncio.get_event_loop()
        deadline = loop.time() + self.scan_timeout

        def _on_detection(dev: BLEDevice, adv: AdvertisementData) -> None:
            name = dev.name or adv.local_name or ""
            mac_match = dev.address.upper() == target or suffix_bytes in name.lower()
            if mac_match and not match:
                log.info("Lock found: %s rssi=%d", name or dev.address, adv.rssi)
                match.append(dev)

        async with BleakScanner(detection_callback=_on_detection):
            # Polling-with-sleep on purpose: we want to break as soon as
            # `_on_detection` fires, but bleak's scanner doesn't expose an
            # asyncio.Event for that — the callback runs synchronously.
            while not match and loop.time() < deadline:  # noqa: ASYNC110
                await asyncio.sleep(0.5)
        return match[0] if match else None

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
        unreliable on this firmware (always 100%); we use the in-band
        protocol value from `query_state()` instead.
        """
        assert self._client is not None
        try:
            data = await self._client.read_gatt_char(BATTERY_CHAR)
            log.debug("Wake-up battery read: %d", data[0] if data else -1)
        except Exception:  # noqa: BLE001  -- non-critical wake nudge
            log.debug("Battery read skipped", exc_info=True)

    def _on_notify(self, _char: BleakGATTCharacteristic, data: bytearray) -> None:
        log.debug("RX %s", bytes(data).hex())
        for frame in self._reassembler.feed(bytes(data)):
            if self._waiting_for_response > 0:
                self._inbox.put_nowait(frame)
            else:
                self._dispatch_event(frame)

    def _dispatch_event(self, frame: Frame) -> None:
        if not self._event_listeners:
            log.debug("Push event with no listeners attached: cmd=0x%02x", frame.command)
            return
        try:
            plain = aes_decrypt(frame.data, self._aes_key)
            echo, status, data = cmd.parse_response_status(plain)
        except (ValueError, RuntimeError) as exc:
            log.warning("Could not decode push event (%s): %s", exc, frame.data.hex())
            return
        event = LockEvent(cmd_echo=echo, status=status, data=data)
        for listener in list(self._event_listeners):
            try:
                listener(event)
            except Exception:
                log.exception("Lock event listener raised; continuing")

    async def _send(self, frame: Frame) -> None:
        assert self._client is not None
        assert self._write_char is not None
        wire = frame.build()
        log.debug("TX %s (%d bytes)", wire.hex(), len(wire))
        for i in range(0, len(wire), _BLE_WRITE_CHUNK):
            await self._client.write_gatt_char(
                self._write_char,
                wire[i : i + _BLE_WRITE_CHUNK],
                response=False,
            )

    async def _recv(self, *, timeout: float = _DEFAULT_RECV_TIMEOUT) -> Frame:  # noqa: ASYNC109  -- timeout is the whole point of this helper
        return await asyncio.wait_for(self._inbox.get(), timeout=timeout)

    async def _exchange(self, frame: Frame, *, timeout: float = _DEFAULT_RECV_TIMEOUT) -> Frame:  # noqa: ASYNC109  -- forwarded to _recv
        # Inbox-vs-event-listener routing in `_on_notify` keys off this flag,
        # so increment around the entire send-then-receive window.
        self._waiting_for_response += 1
        try:
            await self._send(frame)
            try:
                return await self._recv(timeout=timeout)
            except TimeoutError as exc:
                msg = f"Timed out waiting {timeout:.1f}s for the lock to reply"
                raise TTLockError(msg) from exc
        finally:
            self._waiting_for_response -= 1

    async def _check_user_time(self) -> int:
        """Send CHECK_USER_TIME and return the lock's `psFromLock` token."""
        payload = cmd.payload_check_user_time()
        frame = Frame.for_lock(self.key.lockVersion, cmd.CMD_CHECK_USER_TIME, payload).encrypt_data(
            self._aes_key
        )
        resp = await self._exchange(frame)
        log.debug(
            "check_user_time response: cmd=0x%02x encrypt=0x%02x data=%s",
            resp.command,
            resp.encrypt,
            resp.data.hex(),
        )
        plain = aes_decrypt(resp.data, self._aes_key)
        ps = cmd.parse_check_user_time_response(plain)
        log.info("psFromLock = 0x%08x", ps)
        return ps

    async def _auto_lock_exchange(self, payload: bytes) -> tuple[int, int | None]:
        frame = Frame.for_lock(
            self.key.lockVersion, cmd.CMD_AUTO_LOCK_MANAGE, payload
        ).encrypt_data(self._aes_key)
        resp = await self._exchange(frame)
        plain = aes_decrypt(resp.data, self._aes_key)
        log.debug("auto_lock response plaintext: %s", plain.hex())
        return cmd.parse_auto_lock_response(plain)

    async def _keyboard_password_exchange(self, payload: bytes, label: str) -> None:
        frame = Frame.for_lock(
            self.key.lockVersion, cmd.CMD_MANAGE_KEYBOARD_PASSWORD, payload
        ).encrypt_data(self._aes_key)
        resp = await self._exchange(frame)
        plain = aes_decrypt(resp.data, self._aes_key)
        echo, status, data = cmd.parse_response_status(plain)
        log.info(
            "%s response: cmd_echo=0x%02x status=%d data=%s",
            label,
            echo,
            status,
            data.hex(),
        )
        if status != cmd.RESPONSE_SUCCESS:
            raise TTLockError(
                f"Failed to {label}: lock rejected with status={status:#x}, error={data.hex()}"
            )

    async def _control_lock(self, opcode: int, ps: int, label: str) -> None:
        frame = Frame.for_lock(
            self.key.lockVersion,
            opcode,
            cmd.payload_unlock(ps, self.key.unlockKey),
        ).encrypt_data(self._aes_key)
        resp = await self._exchange(frame)
        plain = aes_decrypt(resp.data, self._aes_key)
        echo, status, data = cmd.parse_response_status(plain)
        log.info(
            "%s response: cmd_echo=0x%02x status=%d data=%s",
            label,
            echo,
            status,
            data.hex(),
        )
        if status != cmd.RESPONSE_SUCCESS:
            raise TTLockError(
                f"Failed to {label}: lock rejected with status={status:#x}, error={data.hex()}"
            )
