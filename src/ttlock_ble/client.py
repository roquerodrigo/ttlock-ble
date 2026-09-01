"""TTLockClient: async BLE client driving an already-paired TTLock-family lock."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import TYPE_CHECKING, Self

from . import commands as cmd
from .ble import BleTransport, KeepAlive
from .ble.constants import (
    DEFAULT_KEEP_ALIVE_SECONDS,
    DEVICE_INFO_FIRMWARE_REVISION_CHAR,
    DEVICE_INFO_HARDWARE_REVISION_CHAR,
    DEVICE_INFO_MANUFACTURER_CHAR,
    DEVICE_INFO_MODEL_CHAR,
    DEVICE_INFO_SERIAL_NUMBER_CHAR,
    DEVICE_INFO_SOFTWARE_REVISION_CHAR,
)
from .constants import KeyboardPwdType, LockState
from .crypto import aes_decrypt, hex_key_to_bytes
from .exceptions import TTLockError
from .models import AutoLockLimits, DeviceInfo, FingerprintEntry, LockEvent, LogEntry
from .protocol import Frame

if TYPE_CHECKING:
    import datetime as dt
    from collections.abc import Callable

    from bleak import BleakClient
    from bleak.backends.device import BLEDevice

    from .models import VirtualKey

    DisconnectedCallback = Callable[[BleakClient], None]
    EventListener = Callable[[LockEvent], None]

log: logging.Logger = logging.getLogger("ttlock_ble.client")

# Guards `get_fingerprints` against looping forever if a lock never sends
# the end-of-list response - no confirmed lock has enrolled anywhere near
# this many fingerprints.
_MAX_FINGERPRINT_ENTRIES = 50


class TTLockClient:
    """Async BLE client driving a single, already-paired TTLock-family lock.

    Usage:

        async with TTLockClient(virtual_key) as lock:
            await lock.unlock()

    The client picks the right GATT service, runs the CHECK_USER_TIME
    handshake to obtain `psFromLock`, then issues the actual UNLOCK /
    LOCK / state command.

    The BLE link itself lives in `BleTransport`: this class owns the AES
    key, the command vocabulary and the event listeners, and hands the
    transport the two callbacks that need the key — how to tell a reply
    from a push, and what to do with a push.
    """

    def __init__(
        self,
        key: VirtualKey,
        *,
        device: BLEDevice | None = None,
        scan_timeout: float = 25.0,
        disconnected_callback: DisconnectedCallback | None = None,
        keep_alive_after_command: float = DEFAULT_KEEP_ALIVE_SECONDS,
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
        self._aes_key: bytes = hex_key_to_bytes(key.aesKeyStr)
        self._event_listeners: list[EventListener] = []
        self._command_lock = asyncio.Lock()
        self._transport = BleTransport(
            address=key.lockMac,
            display_name=key.lockAlias or key.lockName or key.lockMac,
            on_push_frame=self._dispatch_event,
            is_response=self._answers,
            device=device,
            scan_timeout=scan_timeout,
            disconnected_callback=disconnected_callback,
        )
        self._keep_alive = KeepAlive(
            window_seconds=keep_alive_after_command,
            poke=self._poke_lock,
            is_connected=lambda: self._transport.is_connected,
            lock_label=key.lockMac,
        )

    @classmethod
    def from_ble_device(
        cls,
        device: BLEDevice,
        key: VirtualKey,
        *,
        disconnected_callback: DisconnectedCallback | None = None,
        keep_alive_after_command: float = DEFAULT_KEEP_ALIVE_SECONDS,
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
    def scan_timeout(self) -> float:
        """Seconds the client scans for the lock when no `BLEDevice` was supplied."""
        return self._transport.scan_timeout

    @scan_timeout.setter
    def scan_timeout(self, seconds: float) -> None:
        self._transport.scan_timeout = seconds

    @property
    def is_connected(self) -> bool:
        """True iff a BLE connection is currently open."""
        return self._transport.is_connected

    async def __aenter__(self) -> Self:
        """Connect on entry; disconnect on exit."""
        await self.connect()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        """Release the BLE connection on exit, even when the body raised."""
        await self.disconnect()

    async def connect(self) -> None:
        """Resolve the BLE device (if not supplied), GATT-connect, start notify."""
        await self._transport.connect()

    async def disconnect(self) -> None:
        """Stop the keep-alive window, then tear down the BLE connection."""
        await self._keep_alive.stop()
        await self._transport.disconnect()

    async def unlock(self) -> None:
        """Unlock the door (status=SUCCESS or raises).

        Starts the keep-alive window so push events from the lock flow to
        registered listeners for `keep_alive_after_command` seconds.
        """
        async with self._command_lock:
            ps = await self._check_user_time()
            await self._control_lock(cmd.CMD_UNLOCK, ps, "unlock")
        self._keep_alive.restart()

    async def lock(self) -> None:
        """Re-lock the door (keep-alive applies, same as `unlock`)."""
        async with self._command_lock:
            ps = await self._check_user_time()
            await self._control_lock(cmd.CMD_LOCK, ps, "lock")
        self._keep_alive.restart()

    async def calibrate_time(self, local_time: dt.datetime) -> None:
        """Push a wall-clock time to the lock's RTC, in the lock's local time.

        TTLock locks keep their own clock that drifts (no NTP, no
        gateway). Time-windowed keys, schedules, and unlock-log
        timestamps all rely on it being accurate. HA integrations
        typically call this once on connect and then daily.

        Admin-gated: `self.key` needs the lock's admin password, or
        CHECK_ADMIN fails the same way a missing handshake would (see
        `_admin_handshake`). Writing the clock is a settings change, and
        the firmware gates it like the other ones - `get_lock_time` is a
        read and needs no handshake at all.

        `local_time` is required, and it is **local time**: the lock
        stores the six wall-clock fields it is handed with no offset
        attached, and reports them back the same way in `get_lock_time`
        and in every operation-log record. A lock provisioned by the
        official app is already keeping local time, so handing it UTC
        does not "normalise" anything - it moves the lock's clock by the
        offset and every timestamp it writes from then on. Pass
        `datetime.now()` on a host in the lock's timezone, or an aware
        datetime in it (only the displayed fields are read).
        """
        async with self._command_lock:
            await self._admin_handshake()
            resp = await self._transport.exchange(
                self._frame(cmd.CMD_TIME_CALIBRATE, cmd.payload_time_calibrate(local_time))
            )
            plain = self._decrypt_response(resp, "calibrate_time")
            echo, status, data = self._parse_response_envelope(plain, "calibrate_time")
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

    async def get_lock_time(self) -> dt.datetime:
        """Read the lock's current RTC as a naive `datetime` (lock-local time).

        The lock has no concept of timezone — the returned datetime mirrors
        whatever wall clock was last pushed via `calibrate_time`, which is
        the lock's local time. Useful for measuring drift before deciding
        to recalibrate; `sync_time` combines both steps.

        This one is a plain read: the firmware answers it without the
        admin handshake `calibrate_time` needs.
        """
        async with self._command_lock:
            resp = await self._transport.exchange(
                self._frame(cmd.CMD_GET_LOCK_TIME, cmd.payload_get_lock_time())
            )
            plain = self._decrypt_response(resp, "get_lock_time")
            try:
                lock_time = cmd.parse_get_lock_time_response(plain)
            except (RuntimeError, ValueError) as exc:
                raise TTLockError(f"Failed to read lock time: {exc}") from exc
            log.info("Lock RTC = %s", lock_time.isoformat())
            return lock_time

    async def sync_time(
        self,
        *,
        local_time: dt.datetime,
        drift_threshold_seconds: float = 2.0,
    ) -> float:
        """Read the lock's clock, return drift, recalibrate when it exceeds the threshold.

        Returns the drift in seconds (lock minus reference) BEFORE any
        correction — positive when the lock is ahead, negative when it
        lags. No calibrate frame is sent when
        `abs(drift) <= drift_threshold_seconds`, which avoids briefly
        perturbing the lock's clock on healthy syncs.

        `local_time` is required, and it is **local time** for the same
        reason `calibrate_time` demands it: the lock's RTC carries no
        offset, so a reference on a different clock reads as a drift of
        the whole offset between them and the correction that follows
        moves the lock onto that other clock. An aware datetime is used
        for the time it displays, not the instant it denotes.

        The calibrate step is admin-gated - see `calibrate_time`. A
        within-threshold sync sends no calibrate frame and so needs no
        admin password.
        """
        reference = local_time.replace(tzinfo=None)
        lock_time = await self.get_lock_time()
        drift = (lock_time - reference).total_seconds()
        log.info("sync_time drift = %+.3fs (lock=%s, ref=%s)", drift, lock_time, reference)
        if abs(drift) > drift_threshold_seconds:
            await self.calibrate_time(reference)
        return drift

    def add_event_listener(self, listener: EventListener) -> None:
        """Register a callback for unsolicited push notifications.

        The callback is invoked synchronously on the asyncio event loop
        (from bleak's notification callback) with a `LockEvent` whenever
        the lock pushes a frame that wasn't a response to a command we
        sent (keypad unlock, fingerprint unlock, mechanical key, etc.).
        Keep listeners cheap and offload any work to a queue/task.
        """
        if listener not in self._event_listeners:
            self._event_listeners.append(listener)

    def remove_event_listener(self, listener: EventListener) -> None:
        """Unregister a previously-added listener (no-op if not present)."""
        with contextlib.suppress(ValueError):
            self._event_listeners.remove(listener)

    async def query_state(self) -> tuple[LockState | None, int | None]:
        """Return `(lock_state, battery_pct)`.

        `lock_state`: `LockState.LOCKED`, `LockState.UNLOCKED`, or `None`
        when the lock failed the request or returned an unrecognised byte.
        `battery_pct`: 0-100 or `None` if not reported.

        Doesn't need CHECK_USER_TIME — search-bicycle-status is unauthenticated.
        """
        async with self._command_lock:
            resp = await self._transport.exchange(
                self._frame(cmd.CMD_QUERY_STATE, cmd.payload_query_state())
            )
            plain = self._decrypt_response(resp, "query_state")
            log.debug("state response plaintext: %s", plain.hex())
            try:
                return cmd.parse_lock_status(plain), cmd.parse_state_battery(plain)
            except ValueError as error:
                raise TTLockError(f"Failed to parse query_state response: {error}") from error

    async def get_auto_lock_time(self) -> int:
        """Read the auto-lock delay in seconds (0 = disabled).

        Admin-gated: `self.key` needs the lock's admin password, or
        CHECK_ADMIN fails the same way a missing handshake would (see
        `_admin_handshake`).

        `-1` would only appear if the lock echoed a non-SEARCH op-type
        for this SEARCH request - an anomaly, not a normal outcome; see
        `parse_auto_lock_response`. A genuinely truncated SEARCH reply
        raises `TTLockError` instead of returning `-1`.
        """
        async with self._command_lock:
            seconds, _battery = await self._auto_lock_exchange(
                cmd.payload_auto_lock_search(), "get_auto_lock_time"
            )
        log.info("auto-lock delay: %ds", seconds)
        return seconds

    async def set_auto_lock_time(self, seconds: int) -> None:
        """Set the auto-lock delay in seconds. `0` disables auto-lock entirely.

        Admin-gated - see `get_auto_lock_time`.
        """
        async with self._command_lock:
            await self._auto_lock_exchange(cmd.payload_auto_lock_set(seconds), "set_auto_lock_time")
        log.info("auto-lock delay set to %ds", seconds)

    async def get_auto_lock_limits(self) -> AutoLockLimits:
        """Read the min/max auto-lock delay (seconds) this lock's firmware will accept.

        Admin-gated - see `get_auto_lock_time`. Uses the same SEARCH
        request `get_auto_lock_time` sends - the current value and these
        limits arrive in the same response, but are kept as separate
        methods/types since they're different concerns that just happen
        to share a wire frame; see `AutoLockLimits` for what's actually
        confirmed versus decoded-but-unverified.
        """
        async with self._command_lock:
            plain = await self._auto_lock_round_trip(
                cmd.payload_auto_lock_search(), "get_auto_lock_limits"
            )
            try:
                limits = cmd.parse_auto_lock_limits_response(plain)
            except (RuntimeError, ValueError) as error:
                raise TTLockError(f"Failed to get_auto_lock_limits: {error}") from error
        log.info("auto-lock limits: min=%ds max=%ds", limits.min_allowed, limits.max_allowed)
        return limits

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

        Admin-gated: `self.key` needs the lock's admin password, or
        CHECK_ADMIN fails the same way a missing handshake would (see
        `_admin_handshake`).

        If `code` shares a digit prefix with another active passcode
        (e.g. "1234" and "12345"), the keypad may match the shorter
        stored code first regardless of which one was actually typed -
        confirmed reproducible even via the official app, so this is
        TTLock firmware behavior, not something this library can
        control or detect. Deleting a longer code does not guarantee
        revocation if a shorter prefix of it remains active as its own
        passcode - see `delete_passcode`.
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
        """Remove a single keypad passcode previously installed via `add_passcode`.

        Admin-gated - see `add_passcode`.

        A SUCCESS response here does not guarantee `code` no longer
        unlocks the door: if a shorter digit-prefix of it is still
        active as its own passcode, the keypad may keep accepting it -
        see `add_passcode`'s prefix-matching caveat.
        """
        async with self._command_lock:
            await self._keyboard_password_exchange(
                cmd.payload_passcode_delete(int(pwd_type), code),
                "delete_passcode",
            )

    async def clear_passcodes(self) -> None:
        """Wipe ALL keypad passcodes from the lock. There's no undo.

        Admin-gated - see `add_passcode`.
        """
        async with self._command_lock:
            await self._keyboard_password_exchange(
                cmd.payload_passcode_clear(),
                "clear_passcodes",
            )

    async def get_operation_log(
        self,
        *,
        max_entries: int | None = None,
        from_sequence: int = 0xFFFF,
    ) -> list[LogEntry]:
        """Pull on-device operation-log entries over BLE.

        First request seeds with `from_sequence` — the default `0xFFFF`
        is "give me what I haven't seen since the last sync"; pass a
        concrete sequence to re-fetch already-acknowledged history (the
        TTLock Android SDK does this in its `OperateLogType.ALL` second
        pass). The lock answers with one record per BLE frame on observed
        firmware (DLock-XP V3), and the response's page-level `sequence`
        is the cursor we echo back verbatim to fetch the next record —
        matching `CommandUtil_V3.getOperateLog` in the SDK. Order is
        firmware-dependent: the V3 firmware emits ascending sequences
        (oldest → newest), which means the returned list is also
        ascending; callers that want newest-first should `reversed()` it.

        Termination: an empty page (`total_len == 0`), `last_seq == 0`,
        the cursor failing to advance, or a page composed entirely of
        records we've already seen (some firmware revisions ignore our
        seq hint and re-echo the latest entry, which is what `seen`
        guards against).
        """
        async with self._command_lock:
            all_entries: list[LogEntry] = []
            seen: set[int] = set()
            next_seq = from_sequence
            while True:
                resp = await self._transport.exchange(
                    self._frame(cmd.CMD_GET_OPERATE_LOG, cmd.payload_operate_log_request(next_seq))
                )
                plain = self._decrypt_response(resp, "operate_log")
                log.debug("operate_log response plaintext: %s", plain.hex())
                try:
                    page, last_seq = cmd.parse_operate_log_response(plain)
                except ValueError as error:
                    raise TTLockError(f"Failed to parse operate_log response: {error}") from error
                log.info("Fetched %d log entr(ies), last_sequence=%d", len(page), last_seq)
                if not page:
                    break
                new_entries = [e for e in page if e.record_number not in seen]
                if not new_entries:
                    break
                for entry in new_entries:
                    seen.add(entry.record_number)
                all_entries.extend(new_entries)
                if max_entries is not None and len(all_entries) >= max_entries:
                    return all_entries[:max_entries]
                if last_seq in {0, next_seq}:
                    break
                next_seq = last_seq
            return all_entries

    async def get_fingerprints(self) -> list[FingerprintEntry]:
        """Read every enrolled fingerprint via the confirmed indexed CMD 0x06/0x06 query.

        Admin-gated - see `set_lock_sound`.

        Loops the index from 0, one BLE round-trip per fingerprint, over
        a single connection and a single admin handshake - matching how
        the official app itself was observed doing it (no reconnect per
        index). Stops cleanly at the lock's own end-of-list response.
        Raises `TTLockError` if the lock never sends it within
        `_MAX_FINGERPRINT_ENTRIES` queries, rather than silently
        returning a possibly-incomplete list.

        Known limitation: this cannot detect whether a fingerprint also
        has a cyclic (day-of-week/time-range) restriction - that data
        lives in a separate mechanism (CMD 0x70) this method doesn't
        query. A fingerprint returned here as permanent or timed may in
        practice also be restricted to specific days/hours. Do not treat
        the absence of that information as confirmation a fingerprint is
        unrestricted.

        Both the empty-list case and a real multi-entry result are
        confirmed on hardware - see
        `commands.fingerprint.parse_fingerprint_list_response` for how.
        """
        async with self._command_lock:
            await self._admin_handshake()
            entries: list[FingerprintEntry] = []
            for index in range(_MAX_FINGERPRINT_ENTRIES):
                resp = await self._transport.exchange(
                    self._frame(cmd.CMD_MANAGE_FINGERPRINT, cmd.payload_fingerprint_list(index))
                )
                plain = self._decrypt_response(resp, "get_fingerprints")
                log.debug("fingerprint list response plaintext: %s", plain.hex())
                try:
                    entry = cmd.parse_fingerprint_list_response(plain)
                except (RuntimeError, ValueError) as error:
                    raise TTLockError(f"Failed to get_fingerprints: {error}") from error
                if entry is None:
                    break
                entries.append(entry)
            else:
                raise TTLockError(
                    f"Failed to get_fingerprints: exceeded safety cap of "
                    f"{_MAX_FINGERPRINT_ENTRIES} entries without an end-of-list response"
                )
        log.info("fetched %d fingerprint(s)", len(entries))
        return entries

    async def set_lock_sound(self, *, enabled: bool) -> None:
        """Turn the keypad/lock beep on or off.

        Admin-gated: `self.key` needs the lock's admin password, or
        CHECK_ADMIN fails the same way a missing handshake would (see
        `_admin_handshake`).

        There is no corresponding read/status command - neither
        `query_state()` nor the BLE advertisement payload carries the
        sound setting, and no query opcode for it has been found. A
        raise-free return only means the lock accepted the frame; it is
        not a live readback. Callers that need to display the current
        setting must track the value they last set optimistically (e.g.
        cache it themselves) rather than ask the lock.
        """
        async with self._command_lock:
            await self._admin_handshake()
            resp = await self._transport.exchange(
                self._frame(cmd.CMD_SET_LOCK_SOUND, cmd.payload_set_lock_sound(enabled=enabled))
            )
            plain = self._decrypt_response(resp, "set_lock_sound")
            self._require_success(plain, "set_lock_sound")
        log.info("lock sound set to %s", "on" if enabled else "off")

    async def set_lock_volume(self, level: int) -> None:
        """Set the keypad/lock beep volume, `level` 1 (lowest) to 5 (highest).

        Accepts a plain int or one of the named `LockVolume` members
        (e.g. `LockVolume.HIGH`) - both work, since `LockVolume` is an
        `IntEnum`.

        Admin-gated - see `set_lock_sound`.

        Confirmed on two different physical locks: on speaker-equipped
        hardware all 5 levels were accepted and the volume audibly
        changed; on beeper-only hardware the lock still reports SUCCESS
        but there is no audible change - a harmless no-op, not an error,
        so this is safe to call unconditionally without checking the
        lock's capabilities first.

        Write-only, same limitation as `set_lock_sound` - there is no
        query opcode for the current volume, so a raise-free return only
        means the lock accepted the frame, not a live readback.
        """
        payload = cmd.payload_set_lock_volume(level)
        async with self._command_lock:
            await self._admin_handshake()
            resp = await self._transport.exchange(self._frame(cmd.CMD_SET_LOCK_SOUND, payload))
            plain = self._decrypt_response(resp, "set_lock_volume")
            self._require_success(plain, "set_lock_volume")
        log.info("lock volume set to %d", level)

    async def get_device_info(self) -> DeviceInfo:
        """Read the standard BLE Device Information Service (0x180A), if the lock exposes it.

        Plain unencrypted Bluetooth SIG characteristics - unrelated to
        TTLock's own command protocol, the session AES key, or any
        TTLock account. No handshake needed, unlike every other method
        on this class. See `DeviceInfo` for which fields have actually
        been confirmed on real hardware.
        """
        async with self._command_lock:
            info = DeviceInfo(
                manufacturer=await self._transport.read_optional_char(
                    DEVICE_INFO_MANUFACTURER_CHAR
                ),
                model=await self._transport.read_optional_char(DEVICE_INFO_MODEL_CHAR),
                serial_number=await self._transport.read_optional_char(
                    DEVICE_INFO_SERIAL_NUMBER_CHAR
                ),
                hardware_revision=await self._transport.read_optional_char(
                    DEVICE_INFO_HARDWARE_REVISION_CHAR
                ),
                firmware_revision=await self._transport.read_optional_char(
                    DEVICE_INFO_FIRMWARE_REVISION_CHAR
                ),
                software_revision=await self._transport.read_optional_char(
                    DEVICE_INFO_SOFTWARE_REVISION_CHAR
                ),
            )
        log.info("device info: %s", info)
        return info

    def _frame(self, command: int, payload: bytes) -> Frame:
        """Build and encrypt one command frame for this lock's protocol version."""
        return Frame.for_lock(self.key.lockVersion, command, payload).encrypt_data(self._aes_key)

    async def _poke_lock(self) -> None:
        """Cheapest round-trip that resets the lock's idle timer (keep-alive window)."""
        async with self._command_lock:
            await self._transport.exchange(
                self._frame(cmd.CMD_QUERY_STATE, cmd.payload_query_state())
            )

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
        event = LockEvent.from_payload(echo, status, data)
        for listener in list(self._event_listeners):
            try:
                listener(event)
            except Exception:
                log.exception("Lock event listener raised; continuing")

    def _answers(self, candidate: Frame, expected_command: int) -> bool:
        """Report whether `candidate` is the lock's reply to `expected_command`.

        The comparison has to happen on the decrypted payload. Every
        lock-to-phone frame carries `CMD_RESPONSE` (0x54) in its
        frame-level command byte, whatever it is answering; the opcode
        being echoed is the first byte of the plaintext. Comparing the
        frame byte instead matches nothing and times out every command.

        A frame that will not decode is accepted rather than discarded:
        it is not something we could route to the event listeners
        either, and the caller's own parser reports it with far more
        context than a timeout would.
        """
        try:
            plain = aes_decrypt(candidate.data, self._aes_key)
            echo, _status, _data = cmd.parse_response_status(plain)
        except ValueError, RuntimeError:
            log.debug(
                "Undecodable frame while awaiting 0x%02x; passing it through",
                expected_command,
            )
            return True
        return echo == expected_command

    def _decrypt_response(self, resp: Frame, label: str) -> bytes:
        """Decrypt a command reply, folding decode failures into `TTLockError`.

        `BleTransport.exchange` deliberately passes undecodable frames through
        to the caller, so every command-level decrypt can face garbage bytes;
        the public contract is that `TTLockClient` raises `TTLockError`, never
        a raw `ValueError` from the AES layer.
        """
        try:
            return aes_decrypt(resp.data, self._aes_key)
        except ValueError as error:
            raise TTLockError(f"Failed to decrypt {label} response: {error}") from error

    def _parse_response_envelope(self, plain: bytes, label: str) -> tuple[int, int, bytes]:
        """Split the `[echo][status][data]` envelope, folding parse failures into `TTLockError`."""
        try:
            return cmd.parse_response_status(plain)
        except ValueError as error:
            raise TTLockError(f"Failed to parse {label} response: {error}") from error

    async def _check_user_time(self) -> int:
        """Send CHECK_USER_TIME and return the lock's `psFromLock` token."""
        resp = await self._transport.exchange(
            self._frame(cmd.CMD_CHECK_USER_TIME, cmd.payload_check_user_time())
        )
        log.debug(
            "check_user_time response: cmd=0x%02x encrypt=0x%02x data=%s",
            resp.command,
            resp.encrypt,
            resp.data.hex(),
        )
        plain = self._decrypt_response(resp, "check_user_time")
        try:
            ps = cmd.parse_check_user_time_response(plain)
        except (RuntimeError, ValueError) as error:
            raise TTLockError(f"Failed to validate virtual key with lock: {error}") from error
        log.info("psFromLock = 0x%08x", ps)
        return ps

    async def _admin_handshake(self) -> None:
        """Run CHECK_ADMIN then CHECK_RANDOM - the extra handshake admin-gated commands need.

        Unlike `_check_user_time` (used by unlock/lock, proving only that
        the key is currently valid), this authorizes against the lock's
        admin password. `set_lock_sound`, the keyboard-password commands
        (`add_passcode`/`delete_passcode`/`clear_passcodes`), the
        auto-lock ones
        (`get_auto_lock_time`/`set_auto_lock_time`/`get_auto_lock_limits`)
        and `calibrate_time` all require it - each of those groups
        originally shipped with no handshake at all, and real-hardware
        testing showed the lock rejects them outright without
        CHECK_ADMIN first (same failure signature `set_lock_sound` had
        before this was discovered). Auto-lock hid it longer because its
        parser collapsed a genuine FAILED rejection into the same
        UNKNOWN sentinel a legitimate no-value response returns.

        `get_fingerprints` requires it too, confirmed from the start
        rather than found as a later fix. Not every read needs it,
        though: `get_lock_time` answers without any handshake, while
        `get_fingerprints` - also a read - does not get that exemption.

        Checks the admin password before touching the BLE link: it is
        `""` on a key that never carried one, and `payload_check_admin`
        would otherwise raise a raw `ValueError` from `int("")` - this
        keeps the public contract to `TTLockError` only. The check is on
        the password rather than on `is_admin()` because `userType` is a
        cloud field a locally built key does not carry, while what the
        firmware actually verifies is the password itself.
        """
        if not self.key.adminPs.isdigit():
            raise TTLockError(
                f"Failed to authorize as admin: key {self.key.keyId} carries no admin password"
            )
        resp = await self._transport.exchange(
            self._frame(
                cmd.CMD_CHECK_ADMIN,
                cmd.payload_check_admin(self.key.uid, self.key.adminPs, self.key.lockFlagPos),
            )
        )
        plain = self._decrypt_response(resp, "check_admin")
        try:
            ps_from_lock = cmd.parse_check_admin_response(plain)
        except (RuntimeError, ValueError) as error:
            raise TTLockError(f"Failed to authorize as admin: {error}") from error

        resp = await self._transport.exchange(
            self._frame(
                cmd.CMD_CHECK_RANDOM, cmd.payload_check_random(ps_from_lock, self.key.unlockKey)
            )
        )
        plain = self._decrypt_response(resp, "check_random")
        self._require_success(plain, "check_random")

    async def _auto_lock_round_trip(self, payload: bytes, label: str) -> bytes:
        """Run the admin handshake, then one CMD_AUTO_LOCK_MANAGE exchange, decrypted.

        Shared by `_auto_lock_exchange` and `get_auto_lock_limits` - both
        send the same SEARCH/MODIFY frames and only differ in which
        fields of the response they parse out afterward.
        """
        await self._admin_handshake()
        resp = await self._transport.exchange(self._frame(cmd.CMD_AUTO_LOCK_MANAGE, payload))
        plain = self._decrypt_response(resp, label)
        log.debug("auto_lock response plaintext: %s", plain.hex())
        return plain

    async def _auto_lock_exchange(self, payload: bytes, label: str) -> tuple[int, int | None]:
        plain = await self._auto_lock_round_trip(payload, label)
        try:
            return cmd.parse_auto_lock_response(plain)
        except (RuntimeError, ValueError) as error:
            raise TTLockError(f"Failed to {label}: {error}") from error

    async def _keyboard_password_exchange(self, payload: bytes, label: str) -> None:
        await self._admin_handshake()
        resp = await self._transport.exchange(
            self._frame(cmd.CMD_MANAGE_KEYBOARD_PASSWORD, payload)
        )
        plain = self._decrypt_response(resp, label)
        self._require_success(plain, label)

    async def _control_lock(self, opcode: int, ps: int, label: str) -> None:
        resp = await self._transport.exchange(
            self._frame(opcode, cmd.payload_unlock(ps, self.key.unlockKey))
        )
        plain = self._decrypt_response(resp, label)
        self._require_success(plain, label)

    def _require_success(self, plain: bytes, label: str) -> None:
        """Log the envelope and raise unless the lock reported success."""
        echo, status, data = self._parse_response_envelope(plain, label)
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
