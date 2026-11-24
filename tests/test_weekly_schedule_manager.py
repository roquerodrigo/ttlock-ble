"""WeeklyScheduleManager and Credential over a fake lock, with SN534 reply bytes."""

from __future__ import annotations

import datetime as dt
from unittest.mock import MagicMock

import pytest

import ttlock_ble.credentials.weekly_schedule_manager as manager_mod
from tests.conftest import make_virtual_key
from tests.test_client_ble import FakeBleakClient, _check_admin_plain, _resp_frame, _status_plain
from ttlock_ble import (
    CardEntry,
    Credential,
    CredentialNotFoundError,
    CredentialType,
    FingerprintEntry,
    LockFeature,
    ReplyTimeoutError,
    TTLockClient,
    TTLockError,
    UnsupportedFeatureError,
    Weekday,
    WeeklyWindow,
)
from ttlock_ble.crypto import aes_decrypt, hex_key_to_bytes
from ttlock_ble.protocol import Frame, FrameReassembler

_CARD = Credential.card(0x6195714B)
_MONDAY = WeeklyWindow(Weekday.MONDAY, dt.time(8), dt.time(12))
_THURSDAY = WeeklyWindow(Weekday.THURSDAY, dt.time(18, 30), dt.time(22))
# Replies captured from an SN534 lock for a throwaway card, since deleted.
_RECORD_MONDAY = bytes.fromhex("7001" + "2e01000102046195714b01010008000c00")
_RECORD_THURSDAY = bytes.fromhex("7001" + "2e01000202046195714b010400121e1600")
_ADD_DONE = bytes.fromhex("70012e02")
_CLEAR_DONE = bytes.fromhex("70012e04")
_NOTHING_TO_CLEAR = bytes.fromhex("70001f04")


def _features(*supported: LockFeature) -> bytes:
    mask = sum(1 << feature for feature in supported)
    words = b"".join(((mask >> (32 * i)) & 0xFFFFFFFF).to_bytes(4, "big") for i in range(2))
    return _status_plain(0x01) + bytes([0x3A]) + words


_SCHEDULES = _features(LockFeature.CYCLIC_IC_OR_FINGER_PRINT)


async def _connected(patched_connect) -> tuple[TTLockClient, FakeBleakClient]:
    key = make_virtual_key()
    client = TTLockClient(key, device=MagicMock(), keep_alive_after_command=0)
    fake = FakeBleakClient(key)
    patched_connect(fake)
    await client.connect()
    return client, fake


def _admin(client: TTLockClient) -> list[Frame]:
    return [
        _resp_frame(client.key, 0x41, _check_admin_plain()),
        _resp_frame(client.key, 0x30, _status_plain(0x30)),
    ]


def _replies(client: TTLockClient, *plains: bytes) -> list[Frame]:
    return [_resp_frame(client.key, 0x54, plain) for plain in plains]


def _silence() -> list[list[Frame]]:
    """No reply at all to the next frame, as the lock does for a credential without windows."""
    return [[]]


def _sent(client: TTLockClient, fake: FakeBleakClient) -> list[bytes]:
    aes = hex_key_to_bytes(client.key.aesKeyStr)
    frames = FrameReassembler().feed(b"".join(fake.written))
    return [aes_decrypt(frame.data, aes) for frame in frames if frame.command == 0x70]


class TestCredential:
    def test_card_uses_four_bytes_up_to_the_32_bit_limit(self) -> None:
        assert Credential.card(0xFFFFFFFF).identifier == bytes.fromhex("ffffffff")
        assert Credential.card(0x1_0000_0000).identifier == bytes.fromhex("0000000100000000")
        assert _CARD.card_number == 0x6195714B

    def test_card_number_must_fit(self) -> None:
        with pytest.raises(ValueError, match="8 bytes"):
            Credential.card(-1)

    def test_fingerprint_needs_six_bytes(self) -> None:
        with pytest.raises(ValueError, match="fingerprint id must be 6 bytes, got 4"):
            Credential.fingerprint(bytes(4))
        assert Credential.fingerprint(bytes(6)).card_number is None

    def test_of_listed_entries(self) -> None:
        card = CardEntry(card_id=bytes.fromhex("6195714b"), start_date=None, end_date=None)
        finger = FingerprintEntry(
            fingerprint_id=bytes.fromhex("0001e240"), slot=3, start_date=None, end_date=None
        )
        assert Credential.of(card) == _CARD
        assert Credential.of(finger) == Credential(
            CredentialType.FINGERPRINT, bytes.fromhex("0001e2400003")
        )


class TestGet:
    async def test_walks_the_cursor_until_it_wraps(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _SCHEDULES, _RECORD_MONDAY, _RECORD_THURSDAY, _RECORD_MONDAY),
        ]
        assert await client.weekly_schedules.get(_CARD) == (_MONDAY, _THURSDAY)
        queries = _sent(client, fake)
        assert [query[7:9] for query in queries] == [b"\x00\x00", b"\x00\x01", b"\x00\x02"]

    async def test_silence_means_no_windows_and_reopens_the_link(
        self, patched_connect, monkeypatch
    ) -> None:
        monkeypatch.setattr(manager_mod, "_QUERY_TIMEOUT", 0.05)
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _SCHEDULES),
            *_silence(),
            *_admin(client),
        ]
        assert await client.weekly_schedules.get(_CARD) == ()
        assert fake.disconnected
        assert fake.reply_for_next == []

    async def test_silence_after_records_raises_and_still_reopens(
        self, patched_connect, monkeypatch
    ) -> None:
        monkeypatch.setattr(manager_mod, "_QUERY_TIMEOUT", 0.05)
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _SCHEDULES, _RECORD_MONDAY),
            *_silence(),
            *_admin(client),
        ]
        with pytest.raises(TTLockError, match="no reply after 1 records"):
            await client.weekly_schedules.get(_CARD)
        assert fake.reply_for_next == []

    async def test_reply_for_another_credential(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [*_admin(client), *_replies(client, _SCHEDULES, _RECORD_MONDAY)]
        with pytest.raises(TTLockError, match="different credential"):
            await client.weekly_schedules.get(Credential.card(0x11223344))

    async def test_refusal_is_typed(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _SCHEDULES, bytes.fromhex("700018")),
        ]
        with pytest.raises(CredentialNotFoundError, match="get_weekly_schedule"):
            await client.weekly_schedules.get(_CARD)

    async def test_malformed_envelope(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [*_admin(client), *_replies(client, _SCHEDULES, bytes([0x70]))]
        with pytest.raises(TTLockError, match="Failed to get_weekly_schedule"):
            await client.weekly_schedules.get(_CARD)

    async def test_non_weekly_record(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        monthly = bytes.fromhex("7001" + "2e01000102046195714b02010308000c00")
        fake.reply_for_next = [*_admin(client), *_replies(client, _SCHEDULES, monthly, monthly)]
        with pytest.raises(TTLockError, match="not a weekly window"):
            await client.weekly_schedules.get(_CARD)

    async def test_without_the_feature(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [*_admin(client), *_replies(client, _features(LockFeature.IC))]
        with pytest.raises(UnsupportedFeatureError, match="CYCLIC_IC_OR_FINGER_PRINT"):
            await client.weekly_schedules.get(_CARD)


class TestSet:
    async def test_clears_then_adds_one_record_per_weekday(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _SCHEDULES, _CLEAR_DONE, _ADD_DONE, _ADD_DONE),
        ]
        await client.weekly_schedules.set(_CARD, [_THURSDAY, _MONDAY])
        clear, monday, thursday = _sent(client, fake)
        assert clear == bytes.fromhex("040204") + _CARD.identifier
        assert monday == bytes.fromhex("020204") + _CARD.identifier + bytes(
            [1, 1, 0, 8, 0, 12, 0, 0, 0, 0, 0]
        )
        assert thursday[7:14] == bytes([1, 4, 0, 18, 30, 22, 0])

    async def test_nothing_to_clear_is_not_an_error(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _SCHEDULES, _NOTHING_TO_CLEAR, _ADD_DONE),
        ]
        await client.weekly_schedules.set(_CARD, [_MONDAY])
        assert len(_sent(client, fake)) == 2

    async def test_other_refusals_stop_the_write(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _SCHEDULES, bytes.fromhex("700018")),
        ]
        with pytest.raises(CredentialNotFoundError):
            await client.weekly_schedules.set(_CARD, [_MONDAY])
        assert len(_sent(client, fake)) == 1

    async def test_wrong_echo(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _SCHEDULES, _CLEAR_DONE, _CLEAR_DONE),
        ]
        with pytest.raises(TTLockError, match="Failed to set_weekly_schedule"):
            await client.weekly_schedules.set(_CARD, [_MONDAY])

    async def test_rejects_an_empty_or_repeated_set_before_connecting(self) -> None:
        client = TTLockClient(make_virtual_key())
        with pytest.raises(ValueError, match="at least one window"):
            await client.weekly_schedules.set(_CARD, [])
        with pytest.raises(ValueError, match="one window per weekday"):
            await client.weekly_schedules.set(_CARD, [_MONDAY, _MONDAY])


class TestClear:
    async def test_clear(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [*_admin(client), *_replies(client, _SCHEDULES, _CLEAR_DONE)]
        await client.weekly_schedules.clear(_CARD)
        assert _sent(client, fake) == [bytes.fromhex("040204") + _CARD.identifier]

    async def test_nothing_to_clear(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [*_admin(client), *_replies(client, _SCHEDULES, _NOTHING_TO_CLEAR)]
        await client.weekly_schedules.clear(_CARD)


async def test_transport_timeout_is_a_reply_timeout() -> None:
    client = TTLockClient(make_virtual_key())
    client._transport._client = MagicMock(is_connected=True)
    client._transport._write_char = "w"

    async def _write(*_args: object, **_kwargs: object) -> None:
        return None

    client._transport._client.write_gatt_char = _write
    with pytest.raises(ReplyTimeoutError, match="Timed out"):
        await client._transport.exchange(
            Frame.for_lock(client.key.lockVersion, 0x14, b""), timeout=0.01
        )
