"""TTLockClient BLE I/O paths driven against a fake bleak backend.

`bleak`'s connection, scanning, and GATT layers are mocked so the connect /
discover / notify / exchange / keep-alive machinery runs with no hardware.
Frame bytes are real (built + AES-encrypted) so the protocol round-trips.
"""

from __future__ import annotations

import asyncio
import datetime as dt
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

import pytest

import ttlock_ble.ble.device_finder as device_finder_mod
import ttlock_ble.ble.transport as transport_mod
from tests.conftest import make_virtual_key
from ttlock_ble import DeviceInfo, LockVolume, TTLockClient, VirtualKey
from ttlock_ble import commands as cmd
from ttlock_ble.ble import find_lock_device
from ttlock_ble.ble.constants import (
    BONG_NOTIFY,
    BONG_SERVICE,
    BONG_WRITE,
    DEVICE_INFO_FIRMWARE_REVISION_CHAR,
    DEVICE_INFO_HARDWARE_REVISION_CHAR,
    DEVICE_INFO_MANUFACTURER_CHAR,
    DEVICE_INFO_MODEL_CHAR,
    DEVICE_INFO_SERIAL_NUMBER_CHAR,
    DEVICE_INFO_SOFTWARE_REVISION_CHAR,
    TTL_NOTIFY,
    TTL_SERVICE,
    TTL_WRITE,
)
from ttlock_ble.crypto import aes_encrypt, hex_key_to_bytes
from ttlock_ble.exceptions import TTLockError
from ttlock_ble.protocol import Frame

if TYPE_CHECKING:
    from collections.abc import Callable


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
        self.char_values: dict[str, bytes] = {}
        self.missing_chars: set[str] = set()

    async def start_notify(self, _char: object, cb) -> None:
        self._notify_cb = cb

    async def stop_notify(self, _char: object) -> None:
        self.stopped_notify = True

    async def read_gatt_char(self, uuid: str) -> bytes:
        if self.battery_raises:
            raise RuntimeError("no battery char")
        if uuid in self.missing_chars:
            raise RuntimeError(f"characteristic {uuid} not found")
        return self.char_values.get(uuid, b"\x64")

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

        monkeypatch.setattr(transport_mod, "establish_connection", _establish)

    return _install


class TestConnect:
    async def test_connect_discovers_chars_and_starts_notify(self, patched_connect) -> None:
        key = make_virtual_key()
        client = TTLockClient(key, device=MagicMock())
        fake = FakeBleakClient(key)
        patched_connect(fake)
        await client.connect()
        assert client.is_connected
        assert client._transport._notify_char == "notify-char"
        assert client._transport._write_char == "write-char"
        await client.disconnect()
        assert fake.disconnected

    async def test_connect_is_idempotent(self, patched_connect) -> None:
        key = make_virtual_key()
        client = TTLockClient(key, device=MagicMock())
        fake = FakeBleakClient(key)
        patched_connect(fake)
        await client.connect()
        # Second connect short-circuits (already connected).
        await client.connect()
        assert client.is_connected

    async def test_connect_uses_bong_service(self, patched_connect) -> None:
        key = make_virtual_key()
        client = TTLockClient(key, device=MagicMock())
        fake = FakeBleakClient(key, service="bong")
        patched_connect(fake)
        await client.connect()
        assert client._transport._notify_char == "notify-char"

    async def test_connect_no_device_and_scan_fails_raises(self, monkeypatch) -> None:
        key = make_virtual_key()
        client = TTLockClient(key)

        async def _no_device(*_a, **_k) -> None:
            return None

        monkeypatch.setattr(transport_mod, "find_lock_device", _no_device)
        with pytest.raises(TTLockError, match="Failed to find lock"):
            await client.connect()

    async def test_connect_establish_failure_wrapped(self, monkeypatch) -> None:
        key = make_virtual_key()
        client = TTLockClient(key, device=MagicMock())

        async def _boom(*_a, **_k) -> None:
            raise OSError("adapter down")

        monkeypatch.setattr(transport_mod, "establish_connection", _boom)
        with pytest.raises(TTLockError, match="Failed to connect"):
            await client.connect()

    async def test_discover_chars_missing_service_raises(self, patched_connect) -> None:
        key = make_virtual_key()
        client = TTLockClient(key, device=MagicMock())
        fake = FakeBleakClient(key)
        fake.services = FakeServices({})  # no usable service
        patched_connect(fake)
        with pytest.raises(TTLockError, match="Failed to discover TTLock GATT"):
            await client.connect()

    async def test_battery_read_failure_is_non_fatal(self, patched_connect) -> None:
        key = make_virtual_key()
        client = TTLockClient(key, device=MagicMock())
        fake = FakeBleakClient(key)
        fake.battery_raises = True
        patched_connect(fake)
        await client.connect()
        assert client.is_connected


@pytest.fixture(autouse=True)
def _fast_sleep(monkeypatch):
    """Make asyncio.sleep instant everywhere the BLE layer awaits it."""
    real_sleep = asyncio.sleep

    async def _sleep(seconds: float) -> None:
        await real_sleep(0)

    monkeypatch.setattr(transport_mod.asyncio, "sleep", _sleep)


class TestDisconnect:
    async def test_disconnect_when_never_connected_is_noop(self) -> None:
        client = TTLockClient(make_virtual_key())
        await client.disconnect()  # must not raise
        assert client._transport._client is None

    async def test_disconnect_swallows_stop_notify_error(self, patched_connect) -> None:
        key = make_virtual_key()
        client = TTLockClient(key, device=MagicMock())
        fake = FakeBleakClient(key)
        fake.stop_notify = AsyncMock(side_effect=RuntimeError("boom"))  # type: ignore[method-assign]
        patched_connect(fake)
        await client.connect()
        await client.disconnect()  # error swallowed on teardown
        assert fake.disconnected


class TestCommands:
    async def _connected(self, patched_connect, *, service: str = "ttl"):
        key = make_virtual_key()
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

    async def test_unlock_check_user_time_rejected_raises_ttlock_error(
        self, patched_connect
    ) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(
                key,
                cmd.CMD_CHECK_USER_TIME,
                _status_plain(cmd.CMD_CHECK_USER_TIME, cmd.RESPONSE_FAILED) + b"\xff",
            )
        ]
        with pytest.raises(TTLockError, match="Failed to validate virtual key"):
            await client.unlock()

    async def test_unlock_undecodable_reply_raises_ttlock_error(self, patched_connect) -> None:
        # _exchange passes undecodable frames through; the command layer must
        # surface them as TTLockError, not as a raw ValueError from the AES layer.
        client, fake, key = await self._connected(patched_connect)
        garbage = Frame(
            protocol_type=key.lockVersion.protocolType,
            sub_version=key.lockVersion.protocolVersion,
            scene=key.lockVersion.scene,
            group_id=key.lockVersion.groupId,
            sub_org=key.lockVersion.orgId,
            command=cmd.CMD_RESPONSE,
            encrypt=0xAA,
            data=b"\x00" * 16,
        )
        fake.reply_for_next = [garbage]
        with pytest.raises(TTLockError, match="Failed to decrypt"):
            await client.unlock()

    async def test_query_state_undecodable_reply_raises_ttlock_error(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        garbage = Frame(
            protocol_type=key.lockVersion.protocolType,
            sub_version=key.lockVersion.protocolVersion,
            scene=key.lockVersion.scene,
            group_id=key.lockVersion.groupId,
            sub_org=key.lockVersion.orgId,
            command=cmd.CMD_RESPONSE,
            encrypt=0xAA,
            data=b"\x00" * 16,
        )
        fake.reply_for_next = [garbage]
        with pytest.raises(TTLockError, match="Failed to decrypt"):
            await client.query_state()

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
            _resp_frame(key, cmd.CMD_CHECK_ADMIN, _check_admin_plain()),
            _resp_frame(key, cmd.CMD_CHECK_RANDOM, _status_plain(cmd.CMD_CHECK_RANDOM)),
            _resp_frame(key, cmd.CMD_TIME_CALIBRATE, _status_plain(cmd.CMD_TIME_CALIBRATE)),
        ]
        await client.calibrate_time(dt.datetime(2026, 5, 20, 12, 0, 0))  # noqa: DTZ001

    async def test_calibrate_time_rejected(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_ADMIN, _check_admin_plain()),
            _resp_frame(key, cmd.CMD_CHECK_RANDOM, _status_plain(cmd.CMD_CHECK_RANDOM)),
            _resp_frame(
                key,
                cmd.CMD_TIME_CALIBRATE,
                _status_plain(cmd.CMD_TIME_CALIBRATE, cmd.RESPONSE_FAILED),
            ),
        ]
        with pytest.raises(TTLockError, match="calibrate"):
            await client.calibrate_time(dt.datetime(2026, 5, 20, 12, 0, 0))  # noqa: DTZ001

    async def test_calibrate_time_admin_check_rejected_raises(self, patched_connect) -> None:
        # The bug this guards against: CMD_TIME_CALIBRATE used to be sent with no
        # handshake at all, and the lock answered status=0x0 err=02 every time.
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(
                key,
                cmd.CMD_CHECK_ADMIN,
                _status_plain(cmd.CMD_CHECK_ADMIN, cmd.RESPONSE_FAILED) + b"\xff",
            )
        ]
        with pytest.raises(TTLockError, match="Failed to authorize as admin"):
            await client.calibrate_time(dt.datetime(2026, 5, 20, 12, 0, 0))  # noqa: DTZ001

    async def test_add_passcode(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_ADMIN, _check_admin_plain()),
            _resp_frame(key, cmd.CMD_CHECK_RANDOM, _status_plain(cmd.CMD_CHECK_RANDOM)),
            _resp_frame(
                key,
                cmd.CMD_MANAGE_KEYBOARD_PASSWORD,
                _status_plain(cmd.CMD_MANAGE_KEYBOARD_PASSWORD),
            ),
        ]
        await client.add_passcode("1234")

    async def test_add_passcode_rejected(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_ADMIN, _check_admin_plain()),
            _resp_frame(key, cmd.CMD_CHECK_RANDOM, _status_plain(cmd.CMD_CHECK_RANDOM)),
            _resp_frame(
                key,
                cmd.CMD_MANAGE_KEYBOARD_PASSWORD,
                _status_plain(cmd.CMD_MANAGE_KEYBOARD_PASSWORD, cmd.RESPONSE_FAILED),
            ),
        ]
        with pytest.raises(TTLockError, match="add_passcode"):
            await client.add_passcode("1234")

    async def test_add_passcode_admin_check_rejected_raises(self, patched_connect) -> None:
        # The bug this guards against: CMD_MANAGE_KEYBOARD_PASSWORD used to be sent with
        # no handshake at all, and real hardware requiring admin auth rejected it outright.
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(
                key,
                cmd.CMD_CHECK_ADMIN,
                _status_plain(cmd.CMD_CHECK_ADMIN, cmd.RESPONSE_FAILED) + b"\xff",
            )
        ]
        with pytest.raises(TTLockError, match="Failed to authorize as admin"):
            await client.add_passcode("1234")

    async def test_delete_passcode(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_ADMIN, _check_admin_plain()),
            _resp_frame(key, cmd.CMD_CHECK_RANDOM, _status_plain(cmd.CMD_CHECK_RANDOM)),
            _resp_frame(
                key,
                cmd.CMD_MANAGE_KEYBOARD_PASSWORD,
                _status_plain(cmd.CMD_MANAGE_KEYBOARD_PASSWORD),
            ),
        ]
        await client.delete_passcode("1234")

    async def test_clear_passcodes(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_ADMIN, _check_admin_plain()),
            _resp_frame(key, cmd.CMD_CHECK_RANDOM, _status_plain(cmd.CMD_CHECK_RANDOM)),
            _resp_frame(
                key,
                cmd.CMD_MANAGE_KEYBOARD_PASSWORD,
                _status_plain(cmd.CMD_MANAGE_KEYBOARD_PASSWORD),
            ),
        ]
        await client.clear_passcodes()

    async def test_get_auto_lock_time(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        # auto-lock search response after envelope: [battery, op=1, seconds(2 BE)].
        plain = bytes([cmd.CMD_AUTO_LOCK_MANAGE, 0x01, 90, 1]) + (30).to_bytes(2, "big")
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_ADMIN, _check_admin_plain()),
            _resp_frame(key, cmd.CMD_CHECK_RANDOM, _status_plain(cmd.CMD_CHECK_RANDOM)),
            _resp_frame(key, cmd.CMD_AUTO_LOCK_MANAGE, plain),
        ]
        seconds = await client.get_auto_lock_time()
        assert seconds == 30

    async def test_get_auto_lock_time_rejected_raises(self, patched_connect) -> None:
        # Regression guard: a FAILED status must not silently collapse into
        # the "-1 = unknown" sentinel - this masked the missing handshake
        # for as long as it did.
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_ADMIN, _check_admin_plain()),
            _resp_frame(key, cmd.CMD_CHECK_RANDOM, _status_plain(cmd.CMD_CHECK_RANDOM)),
            _resp_frame(
                key,
                cmd.CMD_AUTO_LOCK_MANAGE,
                _status_plain(cmd.CMD_AUTO_LOCK_MANAGE, cmd.RESPONSE_FAILED),
            ),
        ]
        with pytest.raises(TTLockError, match="Failed to get_auto_lock_time"):
            await client.get_auto_lock_time()

    async def test_get_auto_lock_time_admin_check_rejected_raises(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(
                key,
                cmd.CMD_CHECK_ADMIN,
                _status_plain(cmd.CMD_CHECK_ADMIN, cmd.RESPONSE_FAILED) + b"\xff",
            )
        ]
        with pytest.raises(TTLockError, match="Failed to authorize as admin"):
            await client.get_auto_lock_time()

    async def test_auto_lock_rejects_a_key_with_no_admin_password(self, patched_connect) -> None:
        # Guards a raw ValueError leak: adminPs is "" on a key that never
        # carried one, and int("") inside payload_check_admin must not
        # escape as a bare ValueError - the public contract is TTLockError.
        client, fake, key = await self._connected(patched_connect)
        key.userType = ""
        key.adminPs = ""

        with pytest.raises(TTLockError, match="Failed to authorize as admin"):
            await client.get_auto_lock_time()
        assert fake.written == []

    async def test_auto_lock_accepts_an_admin_password_without_a_user_type(
        self, patched_connect
    ) -> None:
        # A key built locally instead of pulled from the cloud carries the
        # admin password but no `userType`, and the firmware verifies the
        # password, not that field.
        client, fake, key = await self._connected(patched_connect)
        key.userType = ""
        plain = bytes([cmd.CMD_AUTO_LOCK_MANAGE, 0x01, 90, 1]) + (30).to_bytes(2, "big")
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_ADMIN, _check_admin_plain()),
            _resp_frame(key, cmd.CMD_CHECK_RANDOM, _status_plain(cmd.CMD_CHECK_RANDOM)),
            _resp_frame(key, cmd.CMD_AUTO_LOCK_MANAGE, plain),
        ]
        assert await client.get_auto_lock_time() == 30

    async def test_set_auto_lock_time(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        # MODIFY ack: [battery, op=2] — no seconds echoed back.
        plain = bytes([cmd.CMD_AUTO_LOCK_MANAGE, 0x01, 90, 2])
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_ADMIN, _check_admin_plain()),
            _resp_frame(key, cmd.CMD_CHECK_RANDOM, _status_plain(cmd.CMD_CHECK_RANDOM)),
            _resp_frame(key, cmd.CMD_AUTO_LOCK_MANAGE, plain),
        ]
        await client.set_auto_lock_time(15)

    async def test_set_auto_lock_time_rejected_raises(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_ADMIN, _check_admin_plain()),
            _resp_frame(key, cmd.CMD_CHECK_RANDOM, _status_plain(cmd.CMD_CHECK_RANDOM)),
            _resp_frame(
                key,
                cmd.CMD_AUTO_LOCK_MANAGE,
                _status_plain(cmd.CMD_AUTO_LOCK_MANAGE, cmd.RESPONSE_FAILED),
            ),
        ]
        with pytest.raises(TTLockError, match="Failed to set_auto_lock_time"):
            await client.set_auto_lock_time(15)

    async def test_get_auto_lock_limits(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        plain = (
            bytes([cmd.CMD_AUTO_LOCK_MANAGE, 0x01, 90, 1])
            + (45).to_bytes(2, "big")
            + (1).to_bytes(2, "big")
            + (900).to_bytes(2, "big")
            + bytes([0x01])
        )
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_ADMIN, _check_admin_plain()),
            _resp_frame(key, cmd.CMD_CHECK_RANDOM, _status_plain(cmd.CMD_CHECK_RANDOM)),
            _resp_frame(key, cmd.CMD_AUTO_LOCK_MANAGE, plain),
        ]
        limits = await client.get_auto_lock_limits()
        assert limits.min_allowed == 1
        assert limits.max_allowed == 900

    async def test_get_auto_lock_limits_rejected_raises(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_ADMIN, _check_admin_plain()),
            _resp_frame(key, cmd.CMD_CHECK_RANDOM, _status_plain(cmd.CMD_CHECK_RANDOM)),
            _resp_frame(
                key,
                cmd.CMD_AUTO_LOCK_MANAGE,
                _status_plain(cmd.CMD_AUTO_LOCK_MANAGE, cmd.RESPONSE_FAILED),
            ),
        ]
        with pytest.raises(TTLockError, match="Failed to get_auto_lock_limits"):
            await client.get_auto_lock_limits()

    async def test_get_auto_lock_limits_admin_check_rejected_raises(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(
                key,
                cmd.CMD_CHECK_ADMIN,
                _status_plain(cmd.CMD_CHECK_ADMIN, cmd.RESPONSE_FAILED) + b"\xff",
            )
        ]
        with pytest.raises(TTLockError, match="Failed to authorize as admin"):
            await client.get_auto_lock_limits()

    async def test_set_lock_sound_on(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_ADMIN, _check_admin_plain()),
            _resp_frame(key, cmd.CMD_CHECK_RANDOM, _status_plain(cmd.CMD_CHECK_RANDOM)),
            _resp_frame(key, cmd.CMD_SET_LOCK_SOUND, _status_plain(cmd.CMD_SET_LOCK_SOUND)),
        ]
        await client.set_lock_sound(enabled=True)

    async def test_set_lock_sound_rejected_raises(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_ADMIN, _check_admin_plain()),
            _resp_frame(key, cmd.CMD_CHECK_RANDOM, _status_plain(cmd.CMD_CHECK_RANDOM)),
            _resp_frame(
                key,
                cmd.CMD_SET_LOCK_SOUND,
                _status_plain(cmd.CMD_SET_LOCK_SOUND, cmd.RESPONSE_FAILED),
            ),
        ]
        with pytest.raises(TTLockError, match="Failed to set_lock_sound"):
            await client.set_lock_sound(enabled=False)

    async def test_set_lock_sound_admin_check_rejected_raises(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(
                key,
                cmd.CMD_CHECK_ADMIN,
                _status_plain(cmd.CMD_CHECK_ADMIN, cmd.RESPONSE_FAILED) + b"\xff",
            )
        ]
        with pytest.raises(TTLockError, match="Failed to authorize as admin"):
            await client.set_lock_sound(enabled=True)

    async def test_admin_handshake_rejects_a_key_with_no_admin_password(
        self, patched_connect
    ) -> None:
        # Guards a raw ValueError leak: adminPs is "" on a key that never
        # carried one, and int("") inside payload_check_admin must not
        # escape as a bare ValueError - the public contract is TTLockError.
        client, fake, key = await self._connected(patched_connect)
        key.userType = ""
        key.adminPs = ""

        with pytest.raises(TTLockError, match="Failed to authorize as admin"):
            await client.add_passcode("1234")
        assert fake.written == []

    async def test_admin_handshake_accepts_an_admin_password_without_a_user_type(
        self, patched_connect
    ) -> None:
        # A key built locally instead of pulled from the cloud carries the
        # admin password but no `userType`, and the firmware verifies the
        # password, not that field.
        client, fake, key = await self._connected(patched_connect)
        key.userType = ""
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_ADMIN, _check_admin_plain()),
            _resp_frame(key, cmd.CMD_CHECK_RANDOM, _status_plain(cmd.CMD_CHECK_RANDOM)),
            _resp_frame(
                key,
                cmd.CMD_MANAGE_KEYBOARD_PASSWORD,
                _status_plain(cmd.CMD_MANAGE_KEYBOARD_PASSWORD),
            ),
        ]
        await client.add_passcode("1234")

    async def test_set_lock_sound_check_random_rejected_raises(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_ADMIN, _check_admin_plain()),
            _resp_frame(
                key,
                cmd.CMD_CHECK_RANDOM,
                _status_plain(cmd.CMD_CHECK_RANDOM, cmd.RESPONSE_FAILED),
            ),
        ]
        with pytest.raises(TTLockError, match="Failed to check_random"):
            await client.set_lock_sound(enabled=True)

    async def test_set_lock_volume(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_ADMIN, _check_admin_plain()),
            _resp_frame(key, cmd.CMD_CHECK_RANDOM, _status_plain(cmd.CMD_CHECK_RANDOM)),
            _resp_frame(key, cmd.CMD_SET_LOCK_SOUND, _status_plain(cmd.CMD_SET_LOCK_SOUND)),
        ]
        await client.set_lock_volume(3)

    async def test_set_lock_volume_rejected_raises(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_ADMIN, _check_admin_plain()),
            _resp_frame(key, cmd.CMD_CHECK_RANDOM, _status_plain(cmd.CMD_CHECK_RANDOM)),
            _resp_frame(
                key,
                cmd.CMD_SET_LOCK_SOUND,
                _status_plain(cmd.CMD_SET_LOCK_SOUND, cmd.RESPONSE_FAILED),
            ),
        ]
        with pytest.raises(TTLockError, match="Failed to set_lock_volume"):
            await client.set_lock_volume(3)

    async def test_set_lock_volume_admin_check_rejected_raises(self, patched_connect) -> None:
        client, fake, key = await self._connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(
                key,
                cmd.CMD_CHECK_ADMIN,
                _status_plain(cmd.CMD_CHECK_ADMIN, cmd.RESPONSE_FAILED) + b"\xff",
            )
        ]
        with pytest.raises(TTLockError, match="Failed to authorize as admin"):
            await client.set_lock_volume(3)

    async def test_set_lock_volume_rejects_out_of_range_before_any_exchange(
        self, patched_connect
    ) -> None:
        client, fake, _key = await self._connected(patched_connect)
        with pytest.raises(ValueError, match="1-5"):
            await client.set_lock_volume(max(LockVolume) + 1)
        assert fake.written == []


class TestDeviceInfo:
    """`get_device_info` reads plain GATT text - no TTLock frame involved."""

    async def _connected(self, patched_connect):
        key = make_virtual_key()
        client = TTLockClient(key, device=MagicMock(), keep_alive_after_command=0)
        fake = FakeBleakClient(key)
        patched_connect(fake)
        await client.connect()
        return client, fake

    async def test_reads_confirmed_fields_leaves_unconfirmed_ones_none(
        self, patched_connect
    ) -> None:
        client, fake = await self._connected(patched_connect)
        fake.char_values = {
            DEVICE_INFO_MANUFACTURER_CHAR: b"Sciener",
            DEVICE_INFO_MODEL_CHAR: b"SN484",
            DEVICE_INFO_HARDWARE_REVISION_CHAR: b"1.2",
            DEVICE_INFO_FIRMWARE_REVISION_CHAR: b"6.5.08.230228",
        }
        fake.missing_chars = {
            DEVICE_INFO_SERIAL_NUMBER_CHAR,
            DEVICE_INFO_SOFTWARE_REVISION_CHAR,
        }

        info = await client.get_device_info()

        assert info.manufacturer == "Sciener"
        assert info.model == "SN484"
        assert info.hardware_revision == "1.2"
        assert info.firmware_revision == "6.5.08.230228"
        assert info.serial_number is None
        assert info.software_revision is None

    async def test_no_device_info_service_leaves_everything_none(self, patched_connect) -> None:
        client, fake = await self._connected(patched_connect)
        fake.missing_chars = {
            DEVICE_INFO_MANUFACTURER_CHAR,
            DEVICE_INFO_MODEL_CHAR,
            DEVICE_INFO_SERIAL_NUMBER_CHAR,
            DEVICE_INFO_HARDWARE_REVISION_CHAR,
            DEVICE_INFO_FIRMWARE_REVISION_CHAR,
            DEVICE_INFO_SOFTWARE_REVISION_CHAR,
        }

        info = await client.get_device_info()

        assert info == DeviceInfo()

    async def test_null_padded_value_is_stripped(self, patched_connect) -> None:
        client, fake = await self._connected(patched_connect)
        fake.char_values = {DEVICE_INFO_MODEL_CHAR: b"SN484\x00\x00\x00"}
        fake.missing_chars = {
            DEVICE_INFO_MANUFACTURER_CHAR,
            DEVICE_INFO_SERIAL_NUMBER_CHAR,
            DEVICE_INFO_HARDWARE_REVISION_CHAR,
            DEVICE_INFO_FIRMWARE_REVISION_CHAR,
            DEVICE_INFO_SOFTWARE_REVISION_CHAR,
        }

        info = await client.get_device_info()

        assert info.model == "SN484"

    async def test_all_null_value_reads_as_none_not_empty_string(self, patched_connect) -> None:
        client, fake = await self._connected(patched_connect)
        fake.char_values = {DEVICE_INFO_MODEL_CHAR: b"\x00\x00\x00"}
        fake.missing_chars = {
            DEVICE_INFO_MANUFACTURER_CHAR,
            DEVICE_INFO_SERIAL_NUMBER_CHAR,
            DEVICE_INFO_HARDWARE_REVISION_CHAR,
            DEVICE_INFO_FIRMWARE_REVISION_CHAR,
            DEVICE_INFO_SOFTWARE_REVISION_CHAR,
        }

        info = await client.get_device_info()

        assert info.model is None


class TestExchangeTimeout:
    async def test_recv_timeout_wrapped(self) -> None:
        key = make_virtual_key()
        client = TTLockClient(key)
        client._transport._client = MagicMock(is_connected=True)
        client._transport._write_char = "w"

        async def _no_write(*_a, **_k) -> None:
            return None

        client._transport._client.write_gatt_char = _no_write  # type: ignore[method-assign]
        frame = Frame.for_lock(key.lockVersion, cmd.CMD_QUERY_STATE, b"")
        with pytest.raises(TTLockError, match="Timed out"):
            await client._transport.exchange(frame, timeout=0.01)


class TestNotifyRouting:
    async def test_notify_dispatches_event_when_not_waiting(self) -> None:
        key = make_virtual_key()
        client = TTLockClient(key)
        events = []
        client.add_event_listener(events.append)
        frame = _resp_frame(key, 0x54, bytes.fromhex("47012a0000"))
        client._transport._on_notify("char", bytearray(frame.build()))
        assert len(events) == 1

    async def test_notify_routes_to_inbox_when_waiting(self) -> None:
        key = make_virtual_key()
        client = TTLockClient(key)
        client._transport._waiting_for_response = 1
        frame = _resp_frame(key, 0x54, bytes.fromhex("47012a0000"))
        client._transport._on_notify("char", bytearray(frame.build()))
        assert client._transport._inbox.qsize() == 1


class TestKeepAlive:
    async def test_unlock_schedules_keep_alive(self, patched_connect) -> None:
        key = make_virtual_key()
        client = TTLockClient(key, device=MagicMock(), keep_alive_after_command=5.0)
        fake = FakeBleakClient(key)
        patched_connect(fake)
        await client.connect()
        fake.reply_for_next = [
            _resp_frame(key, cmd.CMD_CHECK_USER_TIME, _check_user_time_plain()),
            _resp_frame(key, cmd.CMD_UNLOCK, _status_plain(cmd.CMD_UNLOCK)),
        ]
        await client.unlock()
        assert client._keep_alive.task is not None
        # disconnect stops it cleanly.
        await client.disconnect()
        assert client._keep_alive.task is None

    async def test_restart_keep_alive_cancels_previous(self) -> None:
        key = make_virtual_key()
        client = TTLockClient(key, keep_alive_after_command=5.0)
        client._transport._client = MagicMock(is_connected=True)
        client._keep_alive.restart()
        first = client._keep_alive.task
        client._keep_alive.restart()
        assert client._keep_alive.task is not first
        await client._keep_alive.stop()

    async def test_keep_alive_disabled_when_zero(self) -> None:
        client = TTLockClient(make_virtual_key(), keep_alive_after_command=0)
        client._keep_alive.restart()
        assert client._keep_alive.task is None

    async def test_stop_keep_alive_noop_when_none(self) -> None:
        client = TTLockClient(make_virtual_key())
        await client._keep_alive.stop()  # must not raise


class TestContextManager:
    async def test_async_with_connects_and_disconnects(self, patched_connect) -> None:
        key = make_virtual_key()
        client = TTLockClient(key, device=MagicMock(), keep_alive_after_command=0)
        fake = FakeBleakClient(key)
        patched_connect(fake)
        async with client as c:
            assert c.is_connected
        assert fake.disconnected


class TestDispatchNoListeners:
    async def test_push_without_listeners_is_dropped(self) -> None:
        key = make_virtual_key()
        client = TTLockClient(key)
        frame = _resp_frame(key, 0x54, bytes.fromhex("47012a0000"))
        client._dispatch_event(frame)  # no listeners → silent return, must not raise


class TestGetLockTimeError:
    async def test_get_lock_time_parse_error_wrapped(self, patched_connect) -> None:
        key = make_virtual_key()
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
        key = make_virtual_key()
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
        key = make_virtual_key()
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
        await client._keep_alive.run()
        await client.disconnect()

    async def test_keep_alive_loop_stops_on_exchange_error(self, patched_connect) -> None:
        key = make_virtual_key()
        client = TTLockClient(key, device=MagicMock(), keep_alive_after_command=10.0)
        fake = FakeBleakClient(key)
        patched_connect(fake)
        await client.connect()

        async def _boom(*_a, **_k):
            raise TTLockError("link dropped")

        client._transport.exchange = _boom  # type: ignore[method-assign]
        # Loop catches the TTLockError and returns instead of hanging.
        await client._keep_alive.run()
        await client.disconnect()


class TestFindDevice:
    async def test_find_device_matches_by_mac(self, monkeypatch) -> None:
        key = make_virtual_key()

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

        monkeypatch.setattr(device_finder_mod, "BleakScanner", FakeScanner)
        found = await find_lock_device(key.lockMac, 0.01)
        assert found is target

    async def test_find_device_returns_none_on_timeout(self, monkeypatch) -> None:
        key = make_virtual_key()

        class FakeScanner:
            def __init__(self, *, detection_callback) -> None:
                self._cb = detection_callback

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_exc) -> None:
                return None

        monkeypatch.setattr(device_finder_mod, "BleakScanner", FakeScanner)
        found = await find_lock_device(key.lockMac, 0.01)
        assert found is None


def _check_user_time_plain() -> bytes:
    """Build a CHECK_USER_TIME response the client can parse for psFromLock."""
    # echo, status, then a 4-byte psFromLock token (big-endian).
    return bytes([cmd.CMD_CHECK_USER_TIME, 0x01]) + (0x12345678).to_bytes(4, "big")


def _check_admin_plain() -> bytes:
    """Build a CHECK_ADMIN response the client can parse for its random token."""
    return bytes([cmd.CMD_CHECK_ADMIN, 0x01]) + (0x87654321).to_bytes(4, "big")
