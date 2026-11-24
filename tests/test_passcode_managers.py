"""PasscodeManager and AdminPasscodeManager over a fake lock."""

from __future__ import annotations

import datetime as dt
import logging
import traceback
from unittest.mock import MagicMock

import pytest

from tests.conftest import make_virtual_key
from tests.test_client_ble import FakeBleakClient, _check_admin_plain, _resp_frame, _status_plain
from ttlock_ble import (
    CredentialAlreadyExistsError,
    CredentialNotFoundError,
    LockFeature,
    Period,
    Permanent,
    SingleUse,
    TTLockClient,
    TTLockError,
    UnsupportedFeatureError,
    Weekday,
    Weekly,
    WeeklyWindow,
)
from ttlock_ble import commands as cmd
from ttlock_ble.crypto import aes_decrypt, hex_key_to_bytes
from ttlock_ble.protocol import FrameReassembler

_CODE = "38150627"
_ADMIN_CODE = "907135"
_START = dt.datetime(2026, 11, 23, 21, 33)  # noqa: DTZ001 -- lock-local wall clock
_END = dt.datetime(2026, 11, 25, 21, 33)  # noqa: DTZ001 -- lock-local wall clock
_MONDAY_EVENING = Weekly((WeeklyWindow(Weekday.MONDAY, dt.time(17), dt.time(19)),))


async def _connected(patched_connect) -> tuple[TTLockClient, FakeBleakClient]:
    key = make_virtual_key()
    client = TTLockClient(key, device=MagicMock(), keep_alive_after_command=0)
    fake = FakeBleakClient(key)
    patched_connect(fake)
    await client.connect()
    return client, fake


def _features(*supported: LockFeature) -> bytes:
    mask = sum(1 << feature for feature in supported)
    words = b"".join(((mask >> (32 * index)) & 0xFFFFFFFF).to_bytes(4, "big") for index in range(2))
    return _status_plain(cmd.CMD_SEARCH_DEVICE_FEATURE) + bytes([0x3A]) + words


def _admin_session(client: TTLockClient, *replies: bytes) -> list:
    return [
        _resp_frame(client.key, cmd.CMD_CHECK_ADMIN, _check_admin_plain()),
        _resp_frame(client.key, cmd.CMD_CHECK_RANDOM, _status_plain(cmd.CMD_CHECK_RANDOM)),
        *(_resp_frame(client.key, 0x54, reply) for reply in replies),
    ]


def _password_reply(op: int) -> bytes:
    return bytes([cmd.CMD_MANAGE_KEYBOARD_PASSWORD, cmd.RESPONSE_SUCCESS, 0x3A, op])


def _password_refusal(error_code: int) -> bytes:
    return bytes([cmd.CMD_MANAGE_KEYBOARD_PASSWORD, cmd.RESPONSE_FAILED, error_code])


def _sent_payloads(client: TTLockClient, fake: FakeBleakClient) -> list[tuple[int, bytes]]:
    aes = hex_key_to_bytes(client.key.aesKeyStr)
    frames = FrameReassembler().feed(b"".join(fake.written))
    return [(frame.command, aes_decrypt(frame.data, aes)) for frame in frames]


class TestPasscodeManager:
    async def test_add_permanent_by_default(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = _admin_session(client, _password_reply(0x02))
        await client.passcodes.add(_CODE)
        assert _sent_payloads(client, fake)[-1] == (
            cmd.CMD_MANAGE_KEYBOARD_PASSWORD,
            cmd.payload_passcode_create(_CODE, Permanent()),
        )

    async def test_add_single_use(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = _admin_session(client, _password_reply(0x02))
        await client.passcodes.add(_CODE, SingleUse(_START, _END))
        assert _sent_payloads(client, fake)[-1][1] == cmd.payload_passcode_create(
            _CODE, SingleUse(_START, _END)
        )

    async def test_add_weekly_checks_the_feature_then_recovers(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = _admin_session(
            client,
            _features(LockFeature.CYCLIC_PASSCODE_CAN_RECOVERY),
            _password_reply(0x06),
        )
        await client.passcodes.add(_CODE, _MONDAY_EVENING)
        sent = _sent_payloads(client, fake)
        assert sent[-2][0] == cmd.CMD_SEARCH_DEVICE_FEATURE
        assert sent[-1][1] == cmd.payload_passcode_recover_weekly(_CODE, _MONDAY_EVENING)

    async def test_add_weekly_without_the_feature_sends_nothing(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = _admin_session(client, _features(LockFeature.PASSCODE))
        with pytest.raises(UnsupportedFeatureError, match="CYCLIC_PASSCODE_CAN_RECOVERY"):
            await client.passcodes.add(_CODE, _MONDAY_EVENING)
        assert _sent_payloads(client, fake)[-1][0] == cmd.CMD_SEARCH_DEVICE_FEATURE

    async def test_add_rejects_an_inexpressible_schedule_before_connecting(self) -> None:
        client = TTLockClient(make_virtual_key())
        bounded = Weekly(_MONDAY_EVENING.windows, _START, _END)
        with pytest.raises(ValueError, match="date range"):
            await client.passcodes.add(_CODE, bounded)

    async def test_add_duplicate_raises_and_keeps_the_code_private(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = _admin_session(client, _password_refusal(0x14))
        with pytest.raises(CredentialAlreadyExistsError) as error:
            await client.passcodes.add(_CODE)
        assert _CODE not in "".join(traceback.format_exception_only(error.value))

    async def test_modify_checks_the_feature(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = _admin_session(
            client, _features(LockFeature.MODIFY_PASSCODE_FUNCTION), _password_reply(0x05)
        )
        await client.passcodes.modify(_CODE, new_code="51207349", validity=Period(_START, _END))
        assert _sent_payloads(client, fake)[-1][1] == cmd.payload_passcode_modify(
            _CODE, new_code="51207349", validity=Period(_START, _END)
        )

    async def test_modify_without_the_feature(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = _admin_session(client, _features(LockFeature.PASSCODE))
        with pytest.raises(UnsupportedFeatureError, match="MODIFY_PASSCODE_FUNCTION"):
            await client.passcodes.modify(_CODE, new_code="51207349")

    async def test_modify_missing_code(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = _admin_session(
            client, _features(LockFeature.MODIFY_PASSCODE_FUNCTION), _password_refusal(0x15)
        )
        with pytest.raises(CredentialNotFoundError, match="Failed to modify_passcode"):
            await client.passcodes.modify(_CODE, validity=Period(_START, _END))

    async def test_delete_ignores_the_type(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = _admin_session(client, _password_reply(0x03))
        await client.passcodes.delete(_CODE)
        assert _sent_payloads(client, fake)[-1][1] == (
            bytes([0x03, 0x01, len(_CODE)]) + _CODE.encode()
        )

    async def test_clear(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = _admin_session(client, _password_reply(0x01))
        await client.passcodes.clear()
        assert _sent_payloads(client, fake)[-1][1] == bytes([0x01])

    async def test_writes_never_log_the_code(self, patched_connect, caplog) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = _admin_session(client, _password_reply(0x02))
        with caplog.at_level(logging.DEBUG):
            await client.passcodes.add(_CODE, Period(_START, _END))
        assert _CODE not in caplog.text
        assert _CODE.encode().hex() not in caplog.text


class TestAdminPasscodeManager:
    async def test_get(self, patched_connect, caplog) -> None:
        client, fake = await _connected(patched_connect)
        reply = bytes([cmd.CMD_GET_ADMIN_PASSCODE, cmd.RESPONSE_SUCCESS, 0x3A, 6]) + b"907135"
        fake.reply_for_next = _admin_session(client, _features(LockFeature.GET_ADMIN_CODE), reply)
        with caplog.at_level(logging.DEBUG):
            assert await client.admin_passcode.get() == _ADMIN_CODE
        assert _ADMIN_CODE not in caplog.text
        assert _ADMIN_CODE.encode().hex() not in caplog.text

    async def test_get_without_the_feature(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = _admin_session(client, _features(LockFeature.PASSCODE))
        with pytest.raises(UnsupportedFeatureError, match="GET_ADMIN_CODE"):
            await client.admin_passcode.get()

    async def test_get_malformed_reply(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        reply = bytes([cmd.CMD_GET_ADMIN_PASSCODE, cmd.RESPONSE_SUCCESS, 0x3A, 9]) + b"907135"
        fake.reply_for_next = _admin_session(client, _features(LockFeature.GET_ADMIN_CODE), reply)
        with pytest.raises(TTLockError, match="Failed to get_admin_passcode") as error:
            await client.admin_passcode.get()
        assert _ADMIN_CODE not in str(error.value)

    async def test_set(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        reply = bytes([cmd.CMD_SET_ADMIN_PASSCODE, cmd.RESPONSE_SUCCESS, 0x3A])
        fake.reply_for_next = _admin_session(client, reply)
        await client.admin_passcode.set(_ADMIN_CODE)
        assert _sent_payloads(client, fake)[-1] == (
            cmd.CMD_SET_ADMIN_PASSCODE,
            bytes([9, 0, 7, 1, 3, 5]),
        )
