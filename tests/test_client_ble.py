"""TTLockClient BLE I/O paths driven against a fake bleak backend.

`bleak`'s connection, scanning, and GATT layers are mocked so the connect /
discover / notify / exchange / keep-alive machinery runs with no hardware.
Frame bytes are real (built + AES-encrypted) so the protocol round-trips.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

import pytest

import ttlock_ble.client as client_mod
from ttlock_ble import LockVersion, TTLockClient, VirtualKey
from ttlock_ble import commands as cmd
from ttlock_ble.client import (
    BONG_NOTIFY,
    BONG_SERVICE,
    BONG_WRITE,
    TTL_NOTIFY,
    TTL_SERVICE,
    TTL_WRITE,
)
from ttlock_ble.crypto import aes_encrypt, hex_key_to_bytes
from ttlock_ble.exceptions import TTLockError
from ttlock_ble.protocol import Frame

if TYPE_CHECKING:
    from collections.abc import Callable


def _virtual_key() -> VirtualKey:
    return VirtualKey(
        keyId=1,
        lockId=2,
        lockMac="E9:EF:A0:BD:22:1D",
        lockAlias="Apto. 2616",
        lockName="DLock-XP",
        lockVersion=LockVersion(protocolType=5, protocolVersion=3, scene=2, groupId=1, orgId=1),
        aesKeyStr="2c,3d,23,5a,12,9c,74,0a,89,d5,0c,24,a5,3b,83,66",
        unlockKey="375773543",
        lockFlagPos=0,
        timezoneRawOffSet=-10800000,
        userType="110301",
        adminPs="422531259",
    )


def _resp_frame(key: VirtualKey, command: int, plain: bytes) -> Frame:
    aes = hex_key_to_bytes(key.aesKeyStr)
    return Frame(
        protocol_type=key.lockVersion.protocolType,
        sub_version=key.lockVersion.protocolVersion,
        scene=key.lockVersion.scene,
        group_id=key.lockVersion.groupId,
        sub_org=key.lockVersion.orgId,
        command=command,
        encrypt=0xAA,
        data=aes_encrypt(plain, aes),
    )


def _status_plain(echo: int, status: int = cmd.RESPONSE_SUCCESS) -> bytes:
    return bytes([echo, status])


class FakeGATTService:
    def __init__(self, uuid: str, chars: dict[str, object]) -> None:
        self.uuid = uuid
        self._chars = chars

    def get_characteristic(self, uuid: str) -> object:
        return self._chars.get(uuid)


class FakeServices:
    def __init__(self, services: dict[str, FakeGATTService]) -> None:
        self._services = services

    def get_service(self, uuid: str) -> FakeGATTService | None:
        return self._services.get(uuid)


class FakeBleakClient:
    """Minimal BleakClient: routes writes to a reply-feeder, supports notify."""

    def __init__(self, key: VirtualKey, *, service: str = "ttl") -> None:
        self.key = key
        self.is_connected = True
        chars = {
            (TTL_WRITE if service == "ttl" else BONG_WRITE): "write-char",
            (TTL_NOTIFY if service == "ttl" else BONG_NOTIFY): "notify-char",
        }
        svc_uuid = TTL_SERVICE if service == "ttl" else BONG_SERVICE
        self.services = FakeServices({svc_uuid: FakeGATTService(svc_uuid, chars)})
        self._notify_cb: Callable[[object, bytearray], None] | None = None
        self.written: list[bytes] = []
        self.reply_for_next: list[Frame] = []
        self.battery_raises = False
        self.disconnected = False
        self.stopped_notify = False

    async def start_notify(self, _char: object, cb) -> None:
        self._notify_cb = cb

    async def stop_notify(self, _char: object) -> None:
        self.stopped_notify = True

    async def read_gatt_char(self, _uuid: str) -> bytes:
        if self.battery_raises:
            raise RuntimeError("no battery char")
        return b"\x64"

    async def write_gatt_char(self, _char: object, data: bytes, *, response: bool) -> None:  # noqa: ARG002 -- matches bleak's signature; callers pass response= by keyword
        self.written.append(bytes(data))
        # Once the full frame is written, deliver the queued reply via notify.
        if self.reply_for_next and self._notify_cb is not None:
            reply = self.reply_for_next.pop(0)
            self._notify_cb("notify-char", bytearray(reply.build()))

    async def disconnect(self) -> None:
        self.disconnected = True
        self.is_connected = False


@pytest.fixture
def patched_connect(monkeypatch):
    """Patch establish_connection to hand back a FakeBleakClient."""

    def _install(fake: FakeBleakClient) -> None:
        async def _establish(*_args, **_kwargs) -> FakeBleakClient:
            return fake

        monkeypatch.setattr(client_mod, "establish_connection", _establish)

    return _install


class TestConnect:
    async def test_connect_discovers_chars_and_starts_notify(self, patched_connect) -> None:
        key = _virtual_key()
        client = TTLockClient(key, device=MagicMock())
        fake = FakeBleakClient(key)
        patched_connect(fake)
        await client.connect()
        assert client.is_connected
        assert client._notify_char == "notify-char"
        assert client._write_char == "write-char"
        await client.disconnect()
        assert fake.disconnected

    async def test_connect_is_idempotent(self, patched_connect) -> None:
        key = _virtual_key()
        client = TTLockClient(key, device=MagicMock())
        fake = FakeBleakClient(key)
        patched_connect(fake)
        await client.connect()
        # Second connect short-circuits (already connected).
        await client.connect()
        assert client.is_connected

    async def test_connect_uses_bong_service(self, patched_connect) -> None:
        key = _virtual_key()
        client = TTLockClient(key, device=MagicMock())
        fake = FakeBleakClient(key, service="bong")
        patched_connect(fake)
        await client.connect()
        assert client._notify_char == "notify-char"

    async def test_connect_no_device_and_scan_fails_raises(self, monkeypatch) -> None:
        key = _virtual_key()
        client = TTLockClient(key)

        async def _no_device() -> None:
            return None

        monkeypatch.setattr(client, "_find_device", _no_device)
        with pytest.raises(TTLockError, match="Failed to find lock"):
            await client.connect()

    async def test_connect_establish_failure_wrapped(self, monkeypatch) -> None:
        key = _virtual_key()
        client = TTLockClient(key, device=MagicMock())

        async def _boom(*_a, **_k) -> None:
            raise OSError("adapter down")

        monkeypatch.setattr(client_mod, "establish_connection", _boom)
        with pytest.raises(TTLockError, match="Failed to connect"):
            await client.connect()

    async def test_discover_chars_missing_service_raises(self, patched_connect) -> None:
        key = _virtual_key()
        client = TTLockClient(key, device=MagicMock())
        fake = FakeBleakClient(key)
        fake.services = FakeServices({})  # no usable service
        patched_connect(fake)
        with pytest.raises(TTLockError, match="Failed to discover TTLock GATT"):
            await client.connect()

    async def test_battery_read_failure_is_non_fatal(self, patched_connect) -> None:
        key = _virtual_key()
        client = TTLockClient(key, device=MagicMock())
        fake = FakeBleakClient(key)
        fake.battery_raises = True
        patched_connect(fake)
        await client.connect()
        assert client.is_connected


@pytest.fixture(autouse=True)
def _fast_sleep(monkeypatch):
    """Make asyncio.sleep in the client module instant."""
    real_sleep = asyncio.sleep

    async def _sleep(seconds: float) -> None:
        await real_sleep(0)

    monkeypatch.setattr(client_mod.asyncio, "sleep", _sleep)


class TestDisconnect:
    async def test_disconnect_when_never_connected_is_noop(self) -> None:
        client = TTLockClient(_virtual_key())
        await client.disconnect()  # must not raise
        assert client._client is None

    async def test_disconnect_swallows_stop_notify_error(self, patched_connect) -> None:
        key = _virtual_key()
        client = TTLockClient(key, device=MagicMock())
        fake = FakeBleakClient(key)
        fake.stop_notify = AsyncMock(side_effect=RuntimeError("boom"))  # type: ignore[method-assign]
        patched_connect(fake)
        await client.connect()
        await client.disconnect()  # error swallowed on teardown
        assert fake.disconnected


class TestCommands:
    async def _connected(self, patched_connect, *, service: str = "ttl"):
        key = _virtual_key()
        client = TTLockClient(key, device=MagicMock(), keep_alive_after_command=0)
        fake = FakeBleakClient(key, service=service)
        patched_connect(fake)
        await client.connect()
        return client, fake, key

    async def test_unlock_success(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_USER_TIME, _check_user_time_plain()),
            _resp_frame(key, cmd.CMD_UNLOCK, _status_plain(cmd.CMD_UNLOCK)),
        ]
        await client.unlock()
        assert len(fake.written) >= 2

    async def test_unlock_rejected_raises(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_USER_TIME, _check_user_time_plain()),
            _resp_frame(key, cmd.CMD_UNLOCK, _status_plain(cmd.CMD_UNLOCK, cmd.RESPONSE_FAILED)),
        ]
        with pytest.raises(TTLockError, match="Failed to unlock"):
            await client.unlock()

    async def test_lock_success(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_USER_TIME, _check_user_time_plain()),
            _resp_frame(key, cmd.CMD_LOCK, _status_plain(cmd.CMD_LOCK)),
        ]
        await client.lock()

    async def test_query_state(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        # Lock state response: parse_lock_status / parse_state_battery read it.
        plain = bytes([cmd.CMD_QUERY_STATE, 0x01, 0x2C, 0x00, 0x01])
        fake.reply_for_next = [_resp_frame(key, cmd.CMD_QUERY_STATE, plain)]
        state, battery = await client.query_state()
        assert state is not None or battery is not None

    async def test_calibrate_time(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_TIME_CALIBRATE, _status_plain(cmd.CMD_TIME_CALIBRATE))
        ]
        await client.calibrate_time()

    async def test_calibrate_time_rejected(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(
                key,
                cmd.CMD_TIME_CALIBRATE,
                _status_plain(cmd.CMD_TIME_CALIBRATE, cmd.RESPONSE_FAILED),
            )
        ]
        with pytest.raises(TTLockError, match="calibrate"):
            await client.calibrate_time()

    async def test_add_passcode(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(
                key,
                cmd.CMD_MANAGE_KEYBOARD_PASSWORD,
                _status_plain(cmd.CMD_MANAGE_KEYBOARD_PASSWORD),
            )
        ]
        await client.add_passcode("1234")

    async def test_add_passcode_rejected(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(
                key,
                cmd.CMD_MANAGE_KEYBOARD_PASSWORD,
                _status_plain(cmd.CMD_MANAGE_KEYBOARD_PASSWORD, cmd.RESPONSE_FAILED),
            )
        ]
        with pytest.raises(TTLockError, match="add_passcode"):
            await client.add_passcode("1234")

    async def test_delete_passcode(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(
                key,
                cmd.CMD_MANAGE_KEYBOARD_PASSWORD,
                _status_plain(cmd.CMD_MANAGE_KEYBOARD_PASSWORD),
            )
        ]
        await client.delete_passcode("1234")

    async def test_clear_passcodes(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(
                key,
                cmd.CMD_MANAGE_KEYBOARD_PASSWORD,
                _status_plain(cmd.CMD_MANAGE_KEYBOARD_PASSWORD),
            )
        ]
        await client.clear_passcodes()

    async def test_get_auto_lock_time(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        # auto-lock search response after envelope: [battery, op=1, seconds(2 BE)].
        plain = bytes([cmd.CMD_AUTO_LOCK_MANAGE, 0x01, 90, 1]) + (30).to_bytes(2, "big")
        fake.reply_for_next = [_resp_frame(key, cmd.CMD_AUTO_LOCK_MANAGE, plain)]
        seconds = await client.get_auto_lock_time()
        assert seconds == 30

    async def test_set_auto_lock_time(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        # MODIFY ack: [battery, op=2] — no seconds echoed back.
        plain = bytes([cmd.CMD_AUTO_LOCK_MANAGE, 0x01, 90, 2])
        fake.reply_for_next = [_resp_frame(key, cmd.CMD_AUTO_LOCK_MANAGE, plain)]
        await client.set_auto_lock_time(15)


class TestExchangeTimeout:
    async def test_recv_timeout_wrapped(self) -> None:
        key = _virtual_key()
        client = TTLockClient(key)
        client._client = MagicMock(is_connected=True)
        client._write_char = "w"

        async def _no_write(*_a, **_k) -> None:
            return None

        client._client.write_gatt_char = _no_write  # type: ignore[method-assign]
        frame = Frame.for_lock(key.lockVersion, cmd.CMD_QUERY_STATE, b"")
        with pytest.raises(TTLockError, match="Timed out"):
            await client._exchange(frame, timeout=0.01)


class TestNotifyRouting:
    async def test_notify_dispatches_event_when_not_waiting(self) -> None:
        key = _virtual_key()
        client = TTLockClient(key)
        events = []
        client.add_event_listener(events.append)
        frame = _resp_frame(key, 0x54, bytes.fromhex("47012a0000"))
        client._on_notify("char", bytearray(frame.build()))
        assert len(events) == 1

    async def test_notify_routes_to_inbox_when_waiting(self) -> None:
        key = _virtual_key()
        client = TTLockClient(key)
        client._waiting_for_response = 1
        frame = _resp_frame(key, 0x54, bytes.fromhex("47012a0000"))
        client._on_notify("char", bytearray(frame.build()))
        assert client._inbox.qsize() == 1


class TestKeepAlive:
    async def test_unlock_schedules_keep_alive(self, patched_connect) -> None:
        key = _virtual_key()
        client = TTLockClient(key, device=MagicMock(), keep_alive_after_command=5.0)
        fake = FakeBleakClient(key)
        patched_connect(fake)
        await client.connect()
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_USER_TIME, _check_user_time_plain()),
            _resp_frame(key, cmd.CMD_UNLOCK, _status_plain(cmd.CMD_UNLOCK)),
        ]
        await client.unlock()
        assert client._keep_alive_task is not None
        # disconnect stops it cleanly.
        await client.disconnect()
        assert client._keep_alive_task is None

    async def test_restart_keep_alive_cancels_previous(self) -> None:
        key = _virtual_key()
        client = TTLockClient(key, keep_alive_after_command=5.0)
        client._client = MagicMock(is_connected=True)
        client._restart_keep_alive()
        first = client._keep_alive_task
        client._restart_keep_alive()
        assert client._keep_alive_task is not first
        await client._stop_keep_alive()

    async def test_keep_alive_disabled_when_zero(self) -> None:
        client = TTLockClient(_virtual_key(), keep_alive_after_command=0)
        client._restart_keep_alive()
        assert client._keep_alive_task is None

    async def test_stop_keep_alive_noop_when_none(self) -> None:
        client = TTLockClient(_virtual_key())
        await client._stop_keep_alive()  # must not raise


class TestContextManager:
    async def test_async_with_connects_and_disconnects(self, patched_connect) -> None:
        key = _virtual_key()
        client = TTLockClient(key, device=MagicMock(), keep_alive_after_command=0)
        fake = FakeBleakClient(key)
        patched_connect(fake)
        async with client as c:
            assert c.is_connected
        assert fake.disconnected


class TestDispatchNoListeners:
    async def test_push_without_listeners_is_dropped(self) -> None:
        key = _virtual_key()
        client = TTLockClient(key)
        frame = _resp_frame(key, 0x54, bytes.fromhex("47012a0000"))
        client._dispatch_event(frame)  # no listeners → silent return, must not raise


class TestGetLockTimeError:
    async def test_get_lock_time_parse_error_wrapped(self, patched_connect) -> None:
        key = _virtual_key()
        client = TTLockClient(key, device=MagicMock(), keep_alive_after_command=0)
        fake = FakeBleakClient(key)
        patched_connect(fake)
        await client.connect()
        # A SUCCESS envelope with a too-short time body makes the parser raise.
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_GET_LOCK_TIME, bytes([cmd.CMD_GET_LOCK_TIME, 0x01, 0x1A]))
        ]
        with pytest.raises(TTLockError, match="Failed to read lock time"):
            await client.get_lock_time()


class TestGetOperationLog:
    async def test_empty_first_page_returns_nothing(self, patched_connect) -> None:
        key = _virtual_key()
        client = TTLockClient(key, device=MagicMock(), keep_alive_after_command=0)
        fake = FakeBleakClient(key)
        patched_connect(fake)
        await client.connect()
        # total_len == 0 → empty page → loop breaks immediately.
        fake.reply_for_next = [
            _resp_frame(
                key, cmd.CMD_GET_OPERATE_LOG, bytes([cmd.CMD_GET_OPERATE_LOG, 0x01, 0x00, 0x00])
            )
        ]
        assert await client.get_operation_log() == []


class TestKeepAliveLoop:
    async def test_keep_alive_loop_polls_then_exits(self, patched_connect) -> None:
        # _fast_sleep makes asyncio.sleep instant, so the loop iterates quickly;
        # the time.monotonic deadline (tiny window) bounds it.
        key = _virtual_key()
        client = TTLockClient(key, device=MagicMock(), keep_alive_after_command=0.001)
        fake = FakeBleakClient(key)
        patched_connect(fake)
        await client.connect()
        # Each keep-alive poke is a QUERY_STATE exchange; feed a few replies.
        fake.reply_for_next = [
            _resp_frame(
                key, cmd.CMD_QUERY_STATE, bytes([cmd.CMD_QUERY_STATE, 0x01, 0x2C, 0x00, 0x01])
            )
            for _ in range(5)
        ]
        await client._keep_alive_loop()
        await client.disconnect()

    async def test_keep_alive_loop_stops_on_exchange_error(self, patched_connect) -> None:
        key = _virtual_key()
        client = TTLockClient(key, device=MagicMock(), keep_alive_after_command=10.0)
        fake = FakeBleakClient(key)
        patched_connect(fake)
        await client.connect()

        async def _boom(*_a, **_k):
            raise TTLockError("link dropped")

        client._exchange = _boom  # type: ignore[method-assign]
        # Loop catches the TTLockError and returns instead of hanging.
        await client._keep_alive_loop()
        await client.disconnect()


class TestFindDevice:
    async def test_find_device_matches_by_mac(self, monkeypatch) -> None:
        key = _virtual_key()
        client = TTLockClient(key, scan_timeout=0.01)

        target = MagicMock()
        target.address = key.lockMac
        target.name = "DLock-XP"

        class FakeScanner:
            def __init__(self, *, detection_callback) -> None:
                self._cb = detection_callback

            async def __aenter__(self):
                adv = MagicMock(rssi=-50, local_name="DLock-XP")
                self._cb(target, adv)
                return self

            async def __aexit__(self, *_exc) -> None:
                return None

        monkeypatch.setattr(client_mod, "BleakScanner", FakeScanner)
        found = await client._find_device()
        assert found is target

    async def test_find_device_returns_none_on_timeout(self, monkeypatch) -> None:
        key = _virtual_key()
        client = TTLockClient(key, scan_timeout=0.01)

        class FakeScanner:
            def __init__(self, *, detection_callback) -> None:
                self._cb = detection_callback

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_exc) -> None:
                return None

        monkeypatch.setattr(client_mod, "BleakScanner", FakeScanner)
        found = await client._find_device()
        assert found is None


def _check_user_time_plain() -> bytes:
    """Build a CHECK_USER_TIME response the client can parse for psFromLock."""
    # echo, status, then a 4-byte psFromLock token (big-endian).
    return bytes([cmd.CMD_CHECK_USER_TIME, 0x01]) + (0x12345678).to_bytes(4, "big")
