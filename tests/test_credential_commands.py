"""The admin-session plumbing every credential command builds on."""

from __future__ import annotations

import asyncio
import logging
import traceback
from unittest.mock import MagicMock

import pytest

from tests.conftest import make_virtual_key
from tests.test_client_ble import (
    FakeBleakClient,
    _check_admin_plain,
    _resp_frame,
    _status_plain,
)
from ttlock_ble import (
    CardEntry,
    CredentialAlreadyExistsError,
    CredentialNotFoundError,
    FingerprintEntry,
    LockFeature,
    LockRejectedError,
    TTLockClient,
    TTLockError,
    UnsupportedFeatureError,
)
from ttlock_ble import commands as cmd
from ttlock_ble.protocol import Frame

_CARD_ID = bytes.fromhex("8a3f19c2")
_ADD_CARD = bytes([0x02, 0x01])
_FEATURES = (
    _status_plain(cmd.CMD_SEARCH_DEVICE_FEATURE)
    + bytes([0x5A])
    + bytes.fromhex("754cf5f7")
    + bytes.fromhex("00000804")
)


def _card_reply(*data: int) -> bytes:
    return bytes([cmd.CMD_MANAGE_IC_CARD, cmd.RESPONSE_SUCCESS, *data])


def _card_failure(error_code: int) -> bytes:
    return bytes([cmd.CMD_MANAGE_IC_CARD, cmd.RESPONSE_FAILED, error_code])


_WAITING_FOR_CARD = _card_reply(0x64, 0x02, 0x02)
_CARD_READ = _card_reply(0x64, 0x02, 0x01, *_CARD_ID)


def _card_is_read(data: bytes) -> bool:
    return data[2] == 0x01


async def _connected(patched_connect) -> tuple[TTLockClient, FakeBleakClient]:
    key = make_virtual_key()
    client = TTLockClient(key, device=MagicMock(), keep_alive_after_command=0)
    fake = FakeBleakClient(key)
    patched_connect(fake)
    await client.connect()
    return client, fake


def _frames(client: TTLockClient, *plains: bytes) -> list[Frame]:
    return [_resp_frame(client.key, 0x54, plain) for plain in plains]


class TestCredentialCommand:
    async def test_first_success_is_final_without_a_handler(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [_frames(client, _card_reply(0x64, 0x03))]
        data = await client._credential_command(cmd.CMD_MANAGE_IC_CARD, b"\x03", "delete_card")
        assert data == bytes([0x64, 0x03])

    async def test_progress_replies_reach_the_handler_until_the_final_one(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [_frames(client, _WAITING_FOR_CARD, _CARD_READ)]
        seen: list[bytes] = []

        def on_reply(data: bytes) -> bool:
            seen.append(data)
            return _card_is_read(data)

        data = await client._credential_command(
            cmd.CMD_MANAGE_IC_CARD, _ADD_CARD, "add_card", on_reply=on_reply
        )
        assert seen == [_WAITING_FOR_CARD[2:], _CARD_READ[2:]]
        assert data[3:] == _CARD_ID

    async def test_command_received_keeps_waiting(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [_frames(client, _card_failure(0x24), _card_reply(0x64, 0x04))]
        data = await client._credential_command(cmd.CMD_MANAGE_IC_CARD, b"\x04", "clear_cards")
        assert data == bytes([0x64, 0x04])

    async def test_endless_acknowledgements_give_up(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [_frames(client, *[_card_failure(0x24)] * 6)]
        with pytest.raises(TTLockError, match="kept acknowledging without a result"):
            await client._credential_command(cmd.CMD_MANAGE_IC_CARD, b"\x04", "clear_cards")

    async def test_refusal_raises_the_mapped_error(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [_frames(client, _card_failure(0x18))]
        with pytest.raises(CredentialNotFoundError, match="0x18 \\(IC_CARD_NOT_EXIST\\)"):
            await client._credential_command(cmd.CMD_MANAGE_IC_CARD, b"\x03", "delete_card")

    async def test_refusal_after_progress_still_raises(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [_frames(client, _WAITING_FOR_CARD, _card_failure(0x16))]
        with pytest.raises(LockRejectedError) as excinfo:
            await client._credential_command(
                cmd.CMD_MANAGE_IC_CARD, _ADD_CARD, "add_card", on_reply=_card_is_read
            )
        assert excinfo.value.error_code == 0x16

    async def test_empty_refusal_has_no_error_code(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        failed = bytes([cmd.CMD_MANAGE_IC_CARD, cmd.RESPONSE_FAILED])
        fake.reply_for_next = [_frames(client, failed)]
        with pytest.raises(LockRejectedError) as excinfo:
            await client._credential_command(cmd.CMD_MANAGE_IC_CARD, b"\x03", "delete_card")
        assert excinfo.value.error_code is None

    async def test_card_number_stays_out_of_logs(self, patched_connect, caplog) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [_frames(client, _WAITING_FOR_CARD, _CARD_READ)]
        with caplog.at_level(logging.DEBUG, logger="ttlock_ble.client"):
            await client._credential_command(
                cmd.CMD_MANAGE_IC_CARD, _ADD_CARD, "add_card", on_reply=_card_is_read
            )
        messages = "\n".join(record.getMessage() for record in caplog.records)
        assert "add_card accepted by the lock" in messages
        assert _CARD_ID.hex() not in messages.replace(" ", "")
        assert _CARD_READ.hex() not in messages


class TestTransportUntil:
    async def test_each_reply_restarts_the_deadline(self) -> None:
        client = TTLockClient(make_virtual_key())
        transport = client._transport
        transport._client = MagicMock(is_connected=True)
        transport._write_char = "w"

        async def _write(*_args: object, **_kwargs: object) -> None:
            return None

        transport._client.write_gatt_char = _write
        progress, final = _frames(client, _WAITING_FOR_CARD, _CARD_READ)

        async def _deliver() -> None:
            await asyncio.sleep(0.06)
            transport._inbox.put_nowait(progress)
            await asyncio.sleep(0.06)
            transport._inbox.put_nowait(final)

        delivery = asyncio.create_task(_deliver())
        reply = await transport.exchange(
            Frame.for_lock(client.key.lockVersion, cmd.CMD_MANAGE_IC_CARD, _ADD_CARD),
            timeout=0.1,
            until=lambda candidate: candidate is final,
        )
        await delivery
        assert reply is final

    async def test_silence_after_progress_times_out(self) -> None:
        client = TTLockClient(make_virtual_key())
        transport = client._transport
        transport._client = MagicMock(is_connected=True)
        transport._write_char = "w"

        async def _write(*_args: object, **_kwargs: object) -> None:
            transport._inbox.put_nowait(_frames(client, _WAITING_FOR_CARD)[0])

        transport._client.write_gatt_char = _write
        with pytest.raises(TTLockError, match="timed out after"):
            await transport.exchange(
                Frame.for_lock(client.key.lockVersion, cmd.CMD_MANAGE_IC_CARD, _ADD_CARD),
                timeout=0.02,
                until=lambda _candidate: False,
            )
        assert transport._waiting_for_response == 0


class TestRequireFeature:
    async def test_supported_feature_reads_the_mask_once(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [_resp_frame(client.key, 0x54, _FEATURES)]
        await client._require_feature("set_passage_mode", LockFeature.PASSAGE_MODE)
        written = len(fake.written)
        await client._require_feature("set_volume", LockFeature.SOUND_VOLUME_AND_LANGUAGE_SETTING)
        assert len(fake.written) == written

    async def test_missing_feature_raises_before_any_command(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [_resp_frame(client.key, 0x54, _FEATURES)]
        with pytest.raises(UnsupportedFeatureError) as excinfo:
            await client._require_feature("set_lamp", LockFeature.LAMP)
        assert excinfo.value.feature is LockFeature.LAMP
        assert fake.reply_for_next == []

    async def test_public_read_fills_the_cache(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            _resp_frame(client.key, cmd.CMD_CHECK_ADMIN, _check_admin_plain()),
            _resp_frame(client.key, cmd.CMD_CHECK_RANDOM, _status_plain(cmd.CMD_CHECK_RANDOM)),
            _resp_frame(client.key, 0x54, _FEATURES),
        ]
        features = await client.get_device_features()
        written = len(fake.written)
        await client._require_feature("set_passage_mode", LockFeature.PASSAGE_MODE)
        assert client._device_features is features
        assert len(fake.written) == written


class TestPasscodeRefusals:
    @staticmethod
    def _admin_then(client: TTLockClient, error_code: int) -> list[Frame | list[Frame]]:
        return [
            _resp_frame(client.key, cmd.CMD_CHECK_ADMIN, _check_admin_plain()),
            _resp_frame(client.key, cmd.CMD_CHECK_RANDOM, _status_plain(cmd.CMD_CHECK_RANDOM)),
            _resp_frame(
                client.key,
                0x54,
                bytes([cmd.CMD_MANAGE_KEYBOARD_PASSWORD, cmd.RESPONSE_FAILED, error_code]),
            ),
        ]

    async def test_duplicate_passcode(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = self._admin_then(client, 0x14)
        with pytest.raises(CredentialAlreadyExistsError) as excinfo:
            await client.add_passcode("9081726")
        rendered = "".join(traceback.format_exception_only(excinfo.value))
        assert "9081726" not in rendered

    async def test_missing_passcode(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = self._admin_then(client, 0x15)
        with pytest.raises(CredentialNotFoundError, match="Failed to delete_passcode"):
            await client.delete_passcode("9081726")


def test_fingerprint_identifier_joins_id_and_slot() -> None:
    entry = FingerprintEntry(
        fingerprint_id=bytes.fromhex("0001e240"),
        slot=0x0102,
        start_date=None,
        end_date=None,
    )
    assert entry.identifier == bytes.fromhex("0001e2400102")


def test_listed_entries_keep_their_ids_out_of_repr() -> None:
    card = CardEntry(card_id=_CARD_ID, start_date=None, end_date=None)
    finger = FingerprintEntry(
        fingerprint_id=bytes.fromhex("0001e240"), slot=0x0102, start_date=None, end_date=None
    )
    assert _CARD_ID.hex() not in repr(card)
    assert str(_CARD_ID) not in repr(card)
    assert "0001e240" not in repr(finger)
    assert "slot" not in repr(finger)
