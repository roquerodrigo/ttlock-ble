"""CardManager over a fake lock, with the captured SN484 reply bytes."""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
import time
import traceback
from unittest.mock import AsyncMock, MagicMock

import pytest
from bleak.exc import BleakError

import ttlock_ble.ble.transport as transport_mod
import ttlock_ble.credentials.card_manager as card_manager_mod
from tests.conftest import make_virtual_key
from tests.test_card_commands import FIRST_CARD, OPERATIONS, SECOND_CARD
from tests.test_client_ble import FakeBleakClient, _check_admin_plain, _resp_frame, _status_plain
from ttlock_ble import (
    CardAlreadyEnrolledError,
    CardEnrollmentStep,
    CardEntry,
    CardPresentedLateError,
    Credential,
    CredentialAlreadyExistsError,
    CredentialNotFoundError,
    EnrollmentTimeoutError,
    LinkLostError,
    LockFeature,
    Period,
    Permanent,
    ReplyTimeoutError,
    SingleUse,
    StorageFullError,
    TTLockClient,
    TTLockError,
    UnsupportedFeatureError,
    Weekday,
    Weekly,
    WeeklyWindow,
)
from ttlock_ble import commands as cmd
from ttlock_ble.crypto import aes_decrypt, hex_key_to_bytes
from ttlock_ble.protocol import Frame, FrameReassembler

_CARD_NUMBER = 0x55667788
_OTHER_NUMBER = 0x11223344
_CARD = Credential.card(_CARD_NUMBER)
_OTHER_CARD = Credential.card(_OTHER_NUMBER)
_TUESDAY = WeeklyWindow(Weekday.TUESDAY, dt.time(20, 14), dt.time(21, 14))
_FRIDAY = WeeklyWindow(Weekday.FRIDAY, dt.time(20, 14), dt.time(21, 14))
_PERIOD = Period(dt.datetime(2026, 11, 22, 19, 46), dt.datetime(2027, 11, 22, 19, 46))  # noqa: DTZ001
_CLEAR_DONE = bytes.fromhex("70014004")
_ADD_DONE = bytes.fromhex("70014002")
_END_OF_LIST = bytes.fromhex("05015501ffff")
_ALL_FEATURES = (LockFeature.IC, LockFeature.CYCLIC_IC_OR_FINGER_PRINT)


def _plain(operation: str, index: int) -> bytes:
    frames = [f for f in OPERATIONS[operation] if f["direction"] == "RX"]
    return bytes.fromhex(frames[index]["plaintext"])


@pytest.fixture(autouse=True)
def _short_safety_window(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(card_manager_mod, "ENROLL_SAFETY_WINDOW", 0.3)


async def _connected(patched_connect) -> tuple[TTLockClient, FakeBleakClient]:
    key = make_virtual_key()
    client = TTLockClient(key, device=MagicMock(), keep_alive_after_command=0)
    fake = FakeBleakClient(key)
    patched_connect(fake)
    await client.connect()
    return client, fake


def _features(*supported: LockFeature) -> bytes:
    mask = sum(1 << feature for feature in supported)
    words = b"".join(((mask >> (32 * i)) & 0xFFFFFFFF).to_bytes(4, "big") for i in range(2))
    return _status_plain(0x01) + bytes([0x3A]) + words


def _admin(client: TTLockClient) -> list[Frame]:
    return [
        _resp_frame(client.key, 0x41, _check_admin_plain()),
        _resp_frame(client.key, 0x30, _status_plain(0x30)),
    ]


def _replies(client: TTLockClient, *plains: bytes) -> list[Frame]:
    return [_resp_frame(client.key, 0x54, plain) for plain in plains]


def _listing(client: TTLockClient, *entries: bytes) -> list[Frame]:
    """The admin handshake and the card list (entry replies) that `enroll` and `add` read first."""
    return [*_admin(client), *_replies(client, *entries, _end_plain())]


def _enrollment(client: TTLockClient, operation: str = "enroll by tap, permanent") -> list:
    """The waiting reply and the pushed card, which the lock sends after one command."""
    return [_replies(client, _plain(operation, 0), _plain(operation, 1))]


def _refusal(command: int, error_code: int) -> bytes:
    return bytes([command, cmd.RESPONSE_FAILED, error_code])


def _sent(client: TTLockClient, fake: FakeBleakClient) -> list[tuple[int, bytes]]:
    aes = hex_key_to_bytes(client.key.aesKeyStr)
    frames = FrameReassembler().feed(b"".join(fake.written))
    return [(frame.command, aes_decrypt(frame.data, aes)) for frame in frames]


def _card_commands(client: TTLockClient, fake: FakeBleakClient) -> list[bytes]:
    """Every CMD 0x05 payload sent except the list queries (sub-op 1)."""
    return [data for data in _card_traffic(client, fake) if data[0] != 1]


def _card_traffic(client: TTLockClient, fake: FakeBleakClient) -> list[bytes]:
    return [data for command, data in _sent(client, fake) if command == cmd.CMD_MANAGE_IC_CARD]


def _schedule_commands(client: TTLockClient, fake: FakeBleakClient) -> list[bytes]:
    return [data for command, data in _sent(client, fake) if command == cmd.CMD_WEEKLY_SCHEDULE]


class TestEnroll:
    async def test_permanent_sends_nothing_after_the_tap(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC)),
            *_enrollment(client),
        ]
        steps: list[CardEnrollmentStep] = []
        credential = await client.cards.enroll(on_progress=steps.append)
        assert credential == Credential.card(_CARD_NUMBER)
        assert credential.card_number == _CARD_NUMBER
        assert _card_commands(client, fake) == [bytes.fromhex("0201")]
        assert steps == [CardEnrollmentStep.WAITING_FOR_CARD, CardEnrollmentStep.CARD_READ]
        assert fake.reply_for_next == []

    async def test_permanent_validity_object_is_the_same_as_none(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC)),
            *_enrollment(client),
        ]
        await client.cards.enroll(Permanent())
        assert _card_commands(client, fake) == [bytes.fromhex("0201")]

    async def test_the_waiting_reply_is_reported_before_the_card_arrives(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC)),
            *_enrollment(client),
        ]
        order: list[str] = []
        original = client.cards._channel.command

        async def traced(*args, **kwargs) -> bytes:
            data = await original(*args, **kwargs)
            order.append("command returned")
            return data

        client.cards._channel.command = traced
        await client.cards.enroll(on_progress=lambda step: order.append(step.name))
        assert order == ["WAITING_FOR_CARD", "command returned", "CARD_READ"]

    async def test_period_sends_its_dates_as_the_app_does(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        operation = "enroll by tap, timed"
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC)),
            *_enrollment(client, operation),
            *_replies(client, _plain(operation, 2)),
        ]
        credential = await client.cards.enroll(_PERIOD)
        assert credential.identifier == FIRST_CARD
        assert _card_commands(client, fake) == [
            bytes.fromhex("0201"),
            bytes.fromhex("05556677881a0b16132e1b0b16132e"),
        ]

    async def test_weekly_sends_its_dates_then_its_windows(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        operation = "enroll by tap, timed"
        weekly = Weekly((_TUESDAY, _FRIDAY), _PERIOD.start, _PERIOD.end)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(*_ALL_FEATURES)),
            *_enrollment(client, operation),
            *_replies(client, _plain(operation, 2)),
            *_admin(client),
            *_replies(client, _CLEAR_DONE, _ADD_DONE, _ADD_DONE),
        ]
        await client.cards.enroll(weekly)
        assert _card_commands(client, fake)[1] == bytes.fromhex("05556677881a0b16132e1b0b16132e")
        assert _schedule_commands(client, fake) == [
            bytes.fromhex("04020455667788"),
            bytes.fromhex("02020455667788010200140e150e00000000"),
            bytes.fromhex("02020455667788010500140e150e00000000"),
        ]
        assert fake.reply_for_next == []

    async def test_unbounded_weekly_sends_the_permanent_dates(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        operation = "enroll by tap, timed"
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(*_ALL_FEATURES)),
            *_enrollment(client, operation),
            *_replies(client, _plain(operation, 2)),
            *_admin(client),
            *_replies(client, _CLEAR_DONE, _ADD_DONE),
        ]
        await client.cards.enroll(Weekly((_TUESDAY,)))
        assert _card_commands(client, fake)[1] == cmd.payload_card_modify(FIRST_CARD, Permanent())

    async def test_no_card_presented_raises_a_typed_timeout(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC)),
            _replies(client, _plain("enroll by tap, no card presented", 0)),
        ]
        steps: list[CardEnrollmentStep] = []
        with pytest.raises(
            EnrollmentTimeoutError,
            match=r"no card was presented within 0\.05 s, nor during the 0\.3 s",
        ):
            await client.cards.enroll(on_progress=steps.append, timeout=0.05)
        assert steps == [CardEnrollmentStep.WAITING_FOR_CARD]
        assert _card_commands(client, fake) == [bytes.fromhex("0201")]

    async def test_no_card_keeps_listening_until_the_safety_window_ends(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC)),
            _replies(client, _plain("enroll by tap, no card presented", 0)),
        ]
        started = time.monotonic()
        with pytest.raises(EnrollmentTimeoutError):
            await client.cards.enroll(timeout=0.05)
        assert time.monotonic() - started >= 0.3
        assert _card_commands(client, fake) == [bytes.fromhex("0201")]

    def _tap_later(self, client, fake, delay: float) -> None:
        push = _resp_frame(client.key, 0x54, _plain("enroll by tap, permanent", 1))
        asyncio.get_running_loop().call_later(
            delay, fake._notify_cb, "notify-char", bytearray(push.build())
        )

    async def test_a_card_after_the_timeout_is_deleted_and_reported(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC)),
            _replies(client, _plain("enroll by tap, permanent", 0)),
            *_replies(client, _plain("delete one card", 0)),
        ]
        self._tap_later(client, fake, 0.15)
        steps: list[CardEnrollmentStep] = []
        with pytest.raises(CardPresentedLateError, match=r"presented after the 0\.05 s") as raised:
            await client.cards.enroll(on_progress=steps.append, timeout=0.05)
        assert raised.value.removed
        assert "was removed again" in str(raised.value)
        assert _card_commands(client, fake) == [
            bytes.fromhex("0201"),
            bytes.fromhex("0355667788"),
        ]
        assert steps == [CardEnrollmentStep.WAITING_FOR_CARD]
        assert fake.reply_for_next == []

    async def test_a_late_card_that_cannot_be_deleted_says_it_may_still_work(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC)),
            _replies(client, _plain("enroll by tap, permanent", 0)),
            *_replies(client, _refusal(cmd.CMD_MANAGE_IC_CARD, 0x18)),
        ]
        self._tap_later(client, fake, 0.15)
        with pytest.raises(CardPresentedLateError, match="may still open the lock") as raised:
            await client.cards.enroll(timeout=0.05)
        assert not raised.value.removed
        assert "0x18" in str(raised.value)
        assert FIRST_CARD.hex() not in str(raised.value)

    async def test_a_card_inside_the_timeout_is_not_late(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC)),
            _replies(client, _plain("enroll by tap, permanent", 0)),
        ]
        self._tap_later(client, fake, 0.05)
        credential = await client.cards.enroll(timeout=0.25)
        assert credential.card_number == _CARD_NUMBER
        assert _card_commands(client, fake) == [bytes.fromhex("0201")]

    def test_the_late_error_survives_pickling(self) -> None:
        import pickle

        error = pickle.loads(pickle.dumps(CardPresentedLateError("late", removed=True)))  # noqa: S301
        assert (str(error), error.removed) == ("late", True)

    async def test_the_timeout_is_a_reply_timeout_for_existing_handlers(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC)),
            _replies(client, _plain("enroll by tap, no card presented", 0)),
        ]
        with pytest.raises(ReplyTimeoutError):
            await client.cards.enroll(timeout=0.05)

    async def test_a_lock_that_never_answers_is_a_plain_reply_timeout(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC)),
            [],
        ]
        with pytest.raises(ReplyTimeoutError) as raised:
            await client.cards.enroll(timeout=0.05)
        assert not isinstance(raised.value, EnrollmentTimeoutError)

    async def test_an_unexpected_reply_is_an_error(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC)),
            _replies(client, bytes.fromhex("0501440209")),
        ]
        with pytest.raises(TTLockError, match=r"Failed to enroll_card: .*unexpected reply"):
            await client.cards.enroll(timeout=0.05)

    async def test_a_full_lock_raises_storage_full(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC), _refusal(cmd.CMD_MANAGE_IC_CARD, 0x16)),
        ]
        with pytest.raises(StorageFullError, match="enroll_card"):
            await client.cards.enroll()

    async def test_a_refused_validity_deletes_the_card_again(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC)),
            *_enrollment(client, "enroll by tap, timed"),
            *_replies(client, _refusal(cmd.CMD_MANAGE_IC_CARD, 0x20)),
            *_admin(client),
            *_replies(client, _plain("delete one card", 0)),
        ]
        with pytest.raises(TTLockError, match="the new card was deleted again") as raised:
            await client.cards.enroll(_PERIOD)
        assert "0x20" in str(raised.value)
        assert raised.value.__cause__ is not None
        assert _card_commands(client, fake)[-1] == bytes.fromhex("0355667788")
        assert fake.reply_for_next == []

    async def test_a_failed_weekly_step_deletes_the_card_again(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        operation = "enroll by tap, timed"
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(*_ALL_FEATURES)),
            *_enrollment(client, operation),
            *_replies(client, _plain(operation, 2)),
            *_admin(client),
            *_replies(client, _CLEAR_DONE, _refusal(cmd.CMD_WEEKLY_SCHEDULE, 0x20)),
            *_admin(client),
            *_replies(client, _plain("delete one card", 0)),
        ]
        with pytest.raises(TTLockError, match="deleted again") as raised:
            await client.cards.enroll(Weekly((_TUESDAY,)))
        assert "windows cleared, only 0 of 1 written" in str(raised.value)
        assert _card_commands(client, fake)[-1] == bytes.fromhex("0355667788")

    async def test_a_failed_rollback_is_reported_with_the_original_error(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC)),
            *_enrollment(client, "enroll by tap, timed"),
            *_replies(client, _refusal(cmd.CMD_MANAGE_IC_CARD, 0x20)),
            *_admin(client),
            *_replies(client, _refusal(cmd.CMD_MANAGE_IC_CARD, 0x18)),
        ]
        with pytest.raises(TTLockError) as raised:
            await client.cards.enroll(_PERIOD)
        message = str(raised.value)
        assert "0x20" in message
        assert "deleting the new card also failed" in message
        assert "0x18" in message
        assert "permanent, unrestricted" in message
        assert fake.reply_for_next == []

    async def test_a_weekly_card_needs_the_cyclic_feature_before_anything_is_sent(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC)),
        ]
        with pytest.raises(UnsupportedFeatureError, match="CYCLIC_IC_OR_FINGER_PRINT"):
            await client.cards.enroll(Weekly((_TUESDAY,)))
        assert _card_commands(client, fake) == []

    async def test_single_use_is_refused_before_connecting(self) -> None:
        client = TTLockClient(make_virtual_key())
        single = SingleUse(dt.datetime(2026, 1, 1), dt.datetime(2026, 1, 2))  # noqa: DTZ001
        with pytest.raises(ValueError, match="single-use"):
            await client.cards.enroll(single)


class TestAdd:
    @pytest.mark.parametrize(
        ("validity", "payload"),
        [
            (None, bytes([2]) + FIRST_CARD + cmd.START_DATE_SENTINEL + cmd.END_DATE_SENTINEL),
            (_PERIOD, bytes.fromhex("02556677881a0b16132e1b0b16132e")),
        ],
        ids=["permanent", "period"],
    )
    async def test_sends_the_card_and_its_dates(self, patched_connect, validity, payload) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC), bytes.fromhex("05014402")),
        ]
        await client.cards.add(_CARD, validity)
        assert _card_commands(client, fake) == [payload]

    async def test_a_number_above_32_bits_uses_eight_bytes(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC), bytes.fromhex("05014402")),
        ]
        await client.cards.add(Credential.card(0x1_0000_0001))
        assert _card_commands(client, fake)[0][1:9] == bytes.fromhex("0000000100000001")

    async def test_weekly_writes_its_windows_after_the_dates(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(*_ALL_FEATURES), bytes.fromhex("05014402")),
            *_admin(client),
            *_replies(client, _CLEAR_DONE, _ADD_DONE),
        ]
        await client.cards.add(_CARD, Weekly((_TUESDAY,)))
        assert len(_schedule_commands(client, fake)) == 2
        assert fake.reply_for_next == []

    async def test_weekly_failure_deletes_the_card_again(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(*_ALL_FEATURES), bytes.fromhex("05014402")),
            *_admin(client),
            *_replies(client, _CLEAR_DONE, _refusal(cmd.CMD_WEEKLY_SCHEDULE, 0x20)),
            *_admin(client),
            *_replies(client, _plain("delete one card", 0)),
        ]
        with pytest.raises(TTLockError, match=r"Failed to add_card: .*deleted again"):
            await client.cards.add(_CARD, Weekly((_TUESDAY,)))
        assert _card_commands(client, fake)[-1] == bytes.fromhex("0355667788")

    async def test_a_full_lock_raises_storage_full(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC), _refusal(cmd.CMD_MANAGE_IC_CARD, 0x16)),
        ]
        with pytest.raises(StorageFullError, match="add_card"):
            await client.cards.add(_CARD)

    async def test_a_card_the_lock_holds_is_refused_with_nothing_sent(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [*_listing(client, _entry_plain(FIRST_CARD, 1))]
        with pytest.raises(CardAlreadyEnrolledError, match="use modify") as raised:
            await client.cards.add(_CARD, _PERIOD)
        assert isinstance(raised.value, CredentialAlreadyExistsError)
        assert raised.value.restored is None
        assert FIRST_CARD.hex() not in str(raised.value)
        assert _card_commands(client, fake) == []
        assert all(command != cmd.CMD_SEARCH_DEVICE_FEATURE for command, _ in _sent(client, fake))

    async def test_another_held_card_does_not_block_an_add(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client, _entry_plain(SECOND_CARD, 1)),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC), bytes.fromhex("05014402")),
        ]
        await client.cards.add(_CARD)
        assert _card_commands(client, fake)[0][:5] == bytes([2]) + FIRST_CARD

    async def test_bad_input_is_refused_before_connecting(self) -> None:
        client = TTLockClient(make_virtual_key())
        single = SingleUse(dt.datetime(2026, 1, 1), dt.datetime(2026, 1, 2))  # noqa: DTZ001
        with pytest.raises(ValueError, match="single-use"):
            await client.cards.add(_CARD, single)


_HELD = "enroll by tap of a card the lock already holds (app, permanent)"
_END_2027 = bytes([27, 11, 24, 23, 59])
_MODIFY_DONE = bytes.fromhex("05014105")


async def _held_card_run(  # noqa: PLR0913 -- one knob per scenario the tests vary
    patched_connect,
    *,
    entry: bytes | None = None,
    windows: tuple[WeeklyWindow, ...] = (),
    after_tap=lambda _client: [],
    validity=None,
    late_by: float | None = None,
):
    """Enroll while the lock already holds card 0x11223344; return the client, fake and error."""
    client, fake = await _connected(patched_connect)
    client.weekly_schedules.get = AsyncMock(return_value=windows)
    held = entry if entry is not None else _entry_plain(SECOND_CARD, 1)
    push = _resp_frame(client.key, 0x54, _plain(_HELD, 1))
    waiting = _replies(client, _plain(_HELD, 0))
    fake.reply_for_next = [
        *_listing(client, held),
        *_admin(client),
        *_replies(client, _features(*_ALL_FEATURES)),
        waiting if late_by is not None else [*waiting, push],
        *after_tap(client),
    ]
    if late_by is not None:
        asyncio.get_running_loop().call_later(
            late_by, fake._notify_cb, "notify-char", bytearray(push.build())
        )
    try:
        await client.cards.enroll(validity, timeout=0.05 if late_by is not None else 5.0)
    except TTLockError as error:
        return client, fake, error
    return client, fake, None


def _restore_replies(client: TTLockClient) -> list[Frame]:
    return [
        *_admin(client),
        *_replies(client, _MODIFY_DONE),
        *_admin(client),
        *_replies(client, _CLEAR_DONE),
    ]


class TestEnrollHeldCard:
    async def test_a_permanent_card_is_restored_not_deleted(self, patched_connect) -> None:
        client, fake, error = await _held_card_run(patched_connect, after_tap=_restore_replies)
        assert isinstance(error, CardAlreadyEnrolledError)
        assert isinstance(error, CredentialAlreadyExistsError)
        assert error.restored is True
        assert "were restored" in str(error)
        assert _card_commands(client, fake) == [
            bytes.fromhex("0201"),
            cmd.payload_card_modify(SECOND_CARD, Permanent()),
        ]
        assert fake.reply_for_next == []

    async def test_dates_and_windows_are_written_back(self, patched_connect) -> None:
        entry = _entry_plain(SECOND_CARD, 1, end=_END_2027)
        client, fake, error = await _held_card_run(
            patched_connect,
            entry=entry,
            windows=(_TUESDAY,),
            after_tap=lambda c: [
                *_admin(c),
                *_replies(c, _MODIFY_DONE),
                *_admin(c),
                *_replies(c, _CLEAR_DONE, _ADD_DONE),
            ],
        )
        assert isinstance(error, CardAlreadyEnrolledError)
        assert error.restored is True
        end = dt.datetime(2027, 11, 24, 23, 59)  # noqa: DTZ001 -- lock-local wall clock
        restored = Weekly((_TUESDAY,), dt.datetime(2000, 1, 1), end)  # noqa: DTZ001
        assert _card_commands(client, fake)[1] == cmd.payload_card_modify(SECOND_CARD, restored)
        assert _schedule_commands(client, fake) == [
            bytes.fromhex("04020411223344"),
            bytes.fromhex("02020411223344010200140e150e00000000"),
        ]
        assert fake.reply_for_next == []

    async def test_a_dated_card_without_windows_gets_a_period_back(self, patched_connect) -> None:
        start = bytes([26, 12, 1, 8, 0])
        entry = _entry_plain(SECOND_CARD, 1, start=start, end=bytes([26, 12, 10, 18, 0]))
        client, fake, error = await _held_card_run(
            patched_connect, entry=entry, after_tap=_restore_replies
        )
        assert isinstance(error, CardAlreadyEnrolledError)
        period = Period(dt.datetime(2026, 12, 1, 8), dt.datetime(2026, 12, 10, 18))  # noqa: DTZ001
        assert _card_commands(client, fake)[1] == cmd.payload_card_modify(SECOND_CARD, period)

    async def test_the_new_validity_is_not_applied_to_a_card_that_was_held(
        self, patched_connect
    ) -> None:
        client, fake, error = await _held_card_run(
            patched_connect, validity=_PERIOD, after_tap=_restore_replies
        )
        assert isinstance(error, CardAlreadyEnrolledError)
        assert _card_commands(client, fake)[1] == cmd.payload_card_modify(SECOND_CARD, Permanent())
        assert all(data[0] != 3 for data in _card_commands(client, fake))

    async def test_a_failed_restore_says_the_card_may_be_unrestricted(
        self, patched_connect
    ) -> None:
        client, fake, error = await _held_card_run(
            patched_connect,
            after_tap=lambda c: [
                *_admin(c),
                *_replies(c, _refusal(cmd.CMD_MANAGE_IC_CARD, 0x20)),
            ],
        )
        assert isinstance(error, CardAlreadyEnrolledError)
        assert error.restored is False
        assert "may now be permanent and unrestricted" in str(error)
        assert "0x20" in str(error)
        assert all(data[0] != 3 for data in _card_commands(client, fake))

    async def test_a_card_that_was_held_and_tapped_late_is_restored_not_removed(
        self, patched_connect
    ) -> None:
        client, fake, error = await _held_card_run(
            patched_connect, after_tap=_restore_replies, late_by=0.15
        )
        assert isinstance(error, CardAlreadyEnrolledError)
        assert not isinstance(error, CardPresentedLateError)
        assert error.restored is True
        assert "after the timeout" in str(error)
        assert all(data[0] != 3 for data in _card_commands(client, fake))
        assert fake.reply_for_next == []

    async def test_a_card_not_in_the_list_is_still_deleted_by_a_rollback(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        client.weekly_schedules.get = AsyncMock(return_value=())
        fake.reply_for_next = [
            *_listing(client, _entry_plain(SECOND_CARD, 1)),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC)),
            *_enrollment(client, "enroll by tap, timed"),
            *_replies(client, _refusal(cmd.CMD_MANAGE_IC_CARD, 0x20)),
            *_admin(client),
            *_replies(client, _plain("delete one card", 0)),
        ]
        with pytest.raises(TTLockError, match="deleted again"):
            await client.cards.enroll(_PERIOD)
        assert _card_commands(client, fake)[-1] == bytes.fromhex("0355667788")

    async def test_a_listing_failure_stops_before_add_mode(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        client.weekly_schedules.get = AsyncMock(side_effect=TTLockError("no reply"))
        fake.reply_for_next = [*_listing(client, _entry_plain(SECOND_CARD, 1))]
        with pytest.raises(TTLockError, match="no reply"):
            await client.cards.enroll()
        assert _card_commands(client, fake) == []

    async def test_the_restore_error_keeps_the_card_private(self, patched_connect, caplog) -> None:
        with caplog.at_level(logging.DEBUG):
            _client, _fake, error = await _held_card_run(
                patched_connect, after_tap=_restore_replies
            )
        assert error is not None
        for secret in (SECOND_CARD.hex(), str(_OTHER_NUMBER), hex(_OTHER_NUMBER)):
            assert secret not in caplog.text + str(error)

    def test_the_error_survives_pickling(self) -> None:
        import pickle

        error = CardAlreadyEnrolledError("enroll_card", "held", restored=False)
        copy = pickle.loads(pickle.dumps(error))  # noqa: S301
        assert (str(copy), copy.restored, copy.action) == ("held", False, "enroll_card")


class TestEnrollRecurringFlow:
    async def test_a_recurring_enrollment_sends_the_captured_validity_and_days(
        self, patched_connect
    ) -> None:
        operation = "enroll by tap, recurring (all seven days)"
        captured = [bytes.fromhex(f["plaintext"]) for f in OPERATIONS[operation]]
        client, fake = await _connected(patched_connect)
        window = (dt.time(22, 17), dt.time(23, 17))
        weekly = Weekly(
            tuple(WeeklyWindow(day, *window) for day in Weekday),
            dt.datetime(2026, 11, 24, 0, 0),  # noqa: DTZ001 -- lock-local wall clock
            dt.datetime(2027, 11, 24, 23, 59),  # noqa: DTZ001 -- lock-local wall clock
        )
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(*_ALL_FEATURES)),
            *_enrollment(client, operation),
            *_replies(client, _plain(operation, 2)),
            *_admin(client),
            *_replies(client, _CLEAR_DONE, *([_ADD_DONE] * 7)),
        ]
        credential = await client.cards.enroll(weekly)
        assert credential.identifier == SECOND_CARD
        sent_validity = _card_commands(client, fake)[1]
        assert sent_validity == captured[3]
        captured_adds = {data for data in captured if data[:2] == bytes.fromhex("0202")}
        sent = _schedule_commands(client, fake)
        assert sent[0] == bytes.fromhex("04020411223344")
        assert set(sent[1:]) == captured_adds
        assert len(captured_adds) == 7


class TestModify:
    async def test_period_matches_the_capture_and_clears_the_windows(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        validity = Period(dt.datetime(2026, 11, 19, 1, 0), dt.datetime(2027, 11, 20, 0, 59))  # noqa: DTZ001
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(*_ALL_FEATURES), bytes.fromhex("05014005")),
            *_admin(client),
            *_replies(client, _CLEAR_DONE),
        ]
        await client.cards.modify(_OTHER_CARD, validity)
        assert _card_commands(client, fake) == [bytes.fromhex("05112233441a0b1301001b0b14003b")]
        assert _schedule_commands(client, fake) == [bytes.fromhex("04020411223344")]
        assert fake.reply_for_next == []

    async def test_weekly_matches_the_capture(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        weekly = Weekly(
            (_TUESDAY, _FRIDAY),
            dt.datetime(2026, 11, 19, 1, 0),  # noqa: DTZ001
            dt.datetime(2027, 11, 20, 0, 59),  # noqa: DTZ001
        )
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(*_ALL_FEATURES), bytes.fromhex("05014005")),
            *_admin(client),
            *_replies(client, _CLEAR_DONE, _ADD_DONE, _ADD_DONE),
        ]
        await client.cards.modify(_OTHER_CARD, weekly)
        assert _card_commands(client, fake) == [bytes.fromhex("05112233441a0b1301001b0b14003b")]
        assert _schedule_commands(client, fake) == [
            bytes.fromhex("04020411223344"),
            bytes.fromhex("02020411223344010200140e150e00000000"),
            bytes.fromhex("02020411223344010500140e150e00000000"),
        ]

    async def test_permanent_sends_the_permanent_dates(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(*_ALL_FEATURES), bytes.fromhex("05014005")),
            *_admin(client),
            *_replies(client, _CLEAR_DONE),
        ]
        await client.cards.modify(_CARD, Permanent())
        assert _card_commands(client, fake) == [
            bytes([5]) + FIRST_CARD + cmd.START_DATE_SENTINEL + cmd.END_DATE_SENTINEL
        ]

    async def test_a_lock_without_windows_skips_clearing_them(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.IC), bytes.fromhex("05014005")),
            *_admin(client),
        ]
        await client.cards.modify(_CARD, _PERIOD)
        assert _schedule_commands(client, fake) == []
        assert fake.reply_for_next == []

    async def test_a_missing_card_raises_not_found(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.IC), _refusal(cmd.CMD_MANAGE_IC_CARD, 0x18)),
        ]
        with pytest.raises(CredentialNotFoundError, match="modify_card"):
            await client.cards.modify(_CARD, _PERIOD)
        assert _schedule_commands(client, fake) == []

    async def test_a_failed_window_write_keeps_the_new_dates_and_says_so(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(*_ALL_FEATURES), bytes.fromhex("05014005")),
            *_admin(client),
            *_replies(client, _CLEAR_DONE, _refusal(cmd.CMD_WEEKLY_SCHEDULE, 0x20)),
        ]
        with pytest.raises(TTLockError, match="windows cleared, only 0 of 1 written"):
            await client.cards.modify(_CARD, Weekly((_TUESDAY,)))
        assert [c for c in _card_commands(client, fake) if c[0] == 3] == []


class TestDeleteAndClear:
    async def test_delete_one_matches_the_capture(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.IC), _plain("delete one card", 0)),
        ]
        await client.cards.delete(_CARD)
        assert _card_commands(client, fake) == [bytes.fromhex("0355667788")]

    async def test_delete_a_missing_card_raises_not_found(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.IC), _refusal(cmd.CMD_MANAGE_IC_CARD, 0x18)),
        ]
        with pytest.raises(CredentialNotFoundError, match="delete_card"):
            await client.cards.delete(_CARD)

    async def test_clear_matches_the_capture(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.IC), _plain("clear all cards (app: reset)", 0)),
        ]
        await client.cards.clear()
        assert _card_commands(client, fake) == [bytes.fromhex("04")]

    @pytest.mark.parametrize(
        ("call", "reads_cards_first"),
        [
            (lambda cards: cards.enroll(), True),
            (lambda cards: cards.add(_CARD), True),
            (lambda cards: cards.modify(_CARD, Permanent()), False),
            (lambda cards: cards.delete(_CARD), False),
            (lambda cards: cards.clear(), False),
        ],
        ids=["enroll", "add", "modify", "delete", "clear"],
    )
    async def test_every_write_needs_the_card_feature(
        self, patched_connect, call, reads_cards_first
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *(_listing(client) if reads_cards_first else []),
            *_admin(client),
            *_replies(client, _features(LockFeature.PASSCODE)),
        ]
        with pytest.raises(UnsupportedFeatureError, match="IC"):
            await call(client.cards)
        assert _card_commands(client, fake) == []

    @pytest.mark.parametrize(
        "call",
        [
            lambda cards, other: cards.add(other),
            lambda cards, other: cards.modify(other, Permanent()),
            lambda cards, other: cards.delete(other),
        ],
        ids=["add", "modify", "delete"],
    )
    async def test_a_fingerprint_is_refused_before_connecting(self, call) -> None:
        client = TTLockClient(make_virtual_key())
        with pytest.raises(ValueError, match="expected a card"):
            await call(client.cards, Credential.fingerprint(bytes(6)))

    async def test_a_listed_card_is_addressed_by_its_own_bytes(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        eight = bytes(range(1, 9))
        listed = CardEntry(card_id=eight, start_date=None, end_date=None)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.IC), bytes.fromhex("05014303")),
        ]
        await client.cards.delete(Credential.of(listed))
        assert _card_commands(client, fake) == [bytes([3]) + eight]


def _reopen_and_list(*entries: bytes):
    """The fresh link's replies: the handshake of the reopen, then the cards read again."""
    return lambda client: [*_admin(client), *_replies(client, *entries, _end_plain())]


class TestEnrollLinkDrop:
    """An SN534 lock drops the link about 21 s into an unanswered enrollment."""

    async def _run(
        self,
        patched_connect,
        after_drop,
        *,
        held: tuple[bytes, ...] = (),
        on_drop=None,
    ) -> tuple[TTLockClient, FakeBleakClient, FakeBleakClient, BaseException, float]:
        client, fake = await _connected(patched_connect)
        client.weekly_schedules.get = AsyncMock(return_value=())
        fake.reply_for_next = [
            *_listing(client, *held),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC)),
            _replies(client, _plain("enroll by tap, no card presented", 0)),
        ]
        fresh = FakeBleakClient(client.key)
        fresh.reply_for_next = after_drop(client)

        def drop() -> None:
            patched_connect(fresh)
            if on_drop is not None:
                on_drop(client)
            fake.is_connected = False
            client._transport._on_disconnected(fake)

        loop = asyncio.get_running_loop()
        started = time.monotonic()
        with pytest.raises(TTLockError) as raised:
            await client.cards.enroll(on_progress=lambda _step: loop.call_soon(drop), timeout=5)
        return client, fake, fresh, raised.value, time.monotonic() - started

    async def test_no_new_card_is_a_timeout_on_a_reopened_link(self, patched_connect) -> None:
        client, _fake, fresh, error, elapsed = await self._run(patched_connect, _reopen_and_list())
        assert isinstance(error, EnrollmentTimeoutError)
        assert "dropped the link when it left add mode" in str(error)
        assert isinstance(error.__cause__, LinkLostError)
        assert client._transport._client is fresh
        assert fresh.reply_for_next == []
        assert _card_commands(client, fresh) == []
        assert 0.3 <= elapsed < 5

    async def test_a_card_enrolled_while_the_link_was_down_is_deleted(
        self, patched_connect
    ) -> None:
        client, _fake, fresh, error, _elapsed = await self._run(
            patched_connect,
            lambda client: [
                *_reopen_and_list(_entry_plain(FIRST_CARD, 1))(client),
                *_replies(client, _plain("delete one card", 0)),
            ],
        )
        assert isinstance(error, CardPresentedLateError)
        assert error.removed
        assert "was removed again" in str(error)
        assert _card_commands(client, fresh) == [bytes([3]) + FIRST_CARD]
        assert fresh.reply_for_next == []

    async def test_a_card_that_cannot_be_deleted_says_it_may_still_work(
        self, patched_connect
    ) -> None:
        _client, _fake, _fresh, error, _elapsed = await self._run(
            patched_connect,
            lambda client: [
                *_reopen_and_list(_entry_plain(FIRST_CARD, 1))(client),
                *_replies(client, _refusal(cmd.CMD_MANAGE_IC_CARD, 0x18)),
            ],
        )
        assert isinstance(error, CardPresentedLateError)
        assert not error.removed
        assert "may still open the lock" in str(error)
        assert FIRST_CARD.hex() not in str(error)

    async def test_a_card_held_before_is_never_deleted(self, patched_connect) -> None:
        client, _fake, fresh, error, _elapsed = await self._run(
            patched_connect,
            _reopen_and_list(_entry_plain(SECOND_CARD, 1)),
            held=(_entry_plain(SECOND_CARD, 1),),
        )
        assert isinstance(error, EnrollmentTimeoutError)
        assert _card_commands(client, fresh) == []

    async def test_a_failed_reconnect_says_the_cards_were_not_checked(
        self, patched_connect, monkeypatch
    ) -> None:
        async def _refuse(*_args: object, **_kwargs: object) -> None:
            raise BleakError("out of slots")

        def refuse_connections(_client: TTLockClient) -> None:
            monkeypatch.setattr(transport_mod, "establish_connection", _refuse)

        _client, _fake, _fresh, error, elapsed = await self._run(
            patched_connect, lambda _client: [], on_drop=refuse_connections
        )
        assert isinstance(error, EnrollmentTimeoutError)
        assert "checking the cards afterwards failed" in str(error)
        assert "out of slots" in str(error)
        assert "reconnect and list the cards" in str(error)
        assert elapsed >= 0.3

    async def test_an_unreadable_listing_says_the_cards_were_not_checked(
        self, patched_connect
    ) -> None:
        _client, _fake, _fresh, error, _elapsed = await self._run(
            patched_connect,
            lambda client: [*_admin(client), *_replies(client, bytes([cmd.CMD_MANAGE_IC_CARD]))],
        )
        assert isinstance(error, EnrollmentTimeoutError)
        assert "checking the cards afterwards failed (Failed to get_cards" in str(error)

    async def test_a_drop_before_add_mode_is_a_plain_link_loss(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC)),
            [],
        ]

        def drop() -> None:
            fake.is_connected = False
            client._transport._on_disconnected(fake)

        asyncio.get_running_loop().call_later(0.05, drop)
        with pytest.raises(LinkLostError) as raised:
            await client.cards.enroll(timeout=5)
        assert not isinstance(raised.value, EnrollmentTimeoutError)


def _entry_plain(
    card_id: bytes,
    position: int,
    start: bytes = cmd.START_DATE_SENTINEL,
    end: bytes = cmd.END_DATE_SENTINEL,
) -> bytes:
    data = bytes([0x55, 0x01]) + position.to_bytes(2, "big") + card_id
    return bytes([cmd.CMD_MANAGE_IC_CARD, cmd.RESPONSE_SUCCESS]) + data + start + end


def _end_plain() -> bytes:
    return bytes([cmd.CMD_MANAGE_IC_CARD, cmd.RESPONSE_SUCCESS]) + bytes.fromhex("5501ffff")


class TestList:
    async def test_without_windows_asks_nothing_more(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _entry_plain(FIRST_CARD, 1), _end_plain()),
        ]
        entries = await client.cards.list(include_weekly_windows=False)
        assert [entry.card_id for entry in entries] == [FIRST_CARD]
        assert entries[0].weekly_windows is None
        assert _schedule_commands(client, fake) == []

    async def test_get_cards_delegates_without_windows(self, patched_connect) -> None:
        client, _fake = await _connected(patched_connect)
        client.cards.list = AsyncMock(return_value=[])
        assert await client.get_cards() == []
        client.cards.list.assert_awaited_once_with(include_weekly_windows=False)

    async def test_includes_each_cards_windows(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(
                client,
                _entry_plain(FIRST_CARD, 1),
                _entry_plain(SECOND_CARD, 2),
                _end_plain(),
            ),
        ]
        windows = (_TUESDAY,)
        client.weekly_schedules.get = AsyncMock(side_effect=[windows, ()])
        entries = await client.cards.list()
        assert [entry.weekly_windows for entry in entries] == [windows, ()]
        asked = [call.args[0] for call in client.weekly_schedules.get.await_args_list]
        assert asked == [Credential.of(entry) for entry in entries]

    async def test_reads_windows_from_the_lock(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        record = bytes.fromhex("70012e01000102045566778801010008000c00")
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _entry_plain(FIRST_CARD, 1), _end_plain()),
            *_admin(client),
            *_replies(client, _features(LockFeature.CYCLIC_IC_OR_FINGER_PRINT), record, record),
        ]
        (entry,) = await client.cards.list()
        assert entry.weekly_windows == (WeeklyWindow(Weekday.MONDAY, dt.time(8), dt.time(12)),)

    async def test_a_lock_without_windows_reads_none_and_stops_asking(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(
                client,
                _entry_plain(FIRST_CARD, 1),
                _entry_plain(SECOND_CARD, 2),
                _end_plain(),
            ),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC)),
        ]
        entries = await client.cards.list()
        assert [entry.weekly_windows for entry in entries] == [(), ()]
        assert fake.reply_for_next == []

    async def test_an_empty_lock(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [*_admin(client), *_replies(client, _end_plain())]
        assert await client.cards.list() == []

    async def test_listing_needs_no_card_feature(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [*_admin(client), *_replies(client, _end_plain())]
        await client.cards.list(include_weekly_windows=False)
        assert all(command != cmd.CMD_SEARCH_DEVICE_FEATURE for command, _ in _sent(client, fake))


class TestPrivacy:
    async def test_card_numbers_stay_out_of_logs_reprs_and_errors(
        self, patched_connect, caplog
    ) -> None:
        client, fake = await _connected(patched_connect)
        operation = "enroll by tap, timed"
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(*_ALL_FEATURES)),
            *_enrollment(client, operation),
            *_replies(client, _refusal(cmd.CMD_MANAGE_IC_CARD, 0x20)),
            *_admin(client),
            *_replies(client, _refusal(cmd.CMD_MANAGE_IC_CARD, 0x18)),
        ]
        with caplog.at_level(logging.DEBUG), pytest.raises(TTLockError) as raised:
            await client.cards.enroll(_PERIOD)
        text = caplog.text + "".join(traceback.format_exception(raised.value))
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _entry_plain(FIRST_CARD, 1), _end_plain()),
        ]
        with caplog.at_level(logging.DEBUG):
            (entry,) = await client.cards.list(include_weekly_windows=False)
        text += caplog.text + repr(entry) + repr(Credential.of(entry)) + repr(client.cards)
        for secret in (FIRST_CARD.hex(), str(_CARD_NUMBER), hex(_CARD_NUMBER)):
            assert secret not in text

    async def test_a_timeout_and_a_missing_card_stay_private(self, patched_connect, caplog) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_listing(client),
            *_admin(client),
            *_replies(client, _features(LockFeature.IC)),
            _replies(client, _plain("enroll by tap, no card presented", 0)),
            *_replies(client, _refusal(cmd.CMD_MANAGE_IC_CARD, 0x18)),
        ]
        with caplog.at_level(logging.DEBUG):
            with pytest.raises(EnrollmentTimeoutError) as timeout:
                await client.cards.enroll(timeout=0.05)
            fake.reply_for_next = [
                *_admin(client),
                *_replies(client, _refusal(cmd.CMD_MANAGE_IC_CARD, 0x18)),
            ]
            with pytest.raises(CredentialNotFoundError) as missing:
                await client.cards.delete(_CARD)
        text = caplog.text + str(timeout.value) + str(missing.value)
        for secret in (FIRST_CARD.hex(), str(_CARD_NUMBER), hex(_CARD_NUMBER)):
            assert secret not in text


def test_card_entry_repr_hides_the_id_and_reports_windows() -> None:
    entry = CardEntry(FIRST_CARD, None, None, (_TUESDAY,))
    assert FIRST_CARD.hex() not in repr(entry)
    assert entry.weekly_windows == (_TUESDAY,)
