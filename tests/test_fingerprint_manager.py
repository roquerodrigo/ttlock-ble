"""FingerprintManager over a fake lock, with the captured SN478 and SN484 reply bytes."""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
import pickle
import time
import traceback
from unittest.mock import AsyncMock, MagicMock

import pytest

import ttlock_ble.credentials.fingerprint_manager as fingerprint_manager_mod
from tests.conftest import make_virtual_key
from tests.test_client_ble import FakeBleakClient, _check_admin_plain, _resp_frame, _status_plain
from tests.test_fingerprint_commands import SN478, SN484
from ttlock_ble import (
    Credential,
    CredentialNotFoundError,
    EnrollmentTimeoutError,
    FingerprintEnrolledLateError,
    FingerprintEnrollmentProgress,
    FingerprintEnrollmentStep,
    FingerprintEntry,
    LinkLostError,
    LockFeature,
    LockRejectedError,
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

_FIRST = Credential.fingerprint(bytes.fromhex("3299d6ae0000"))
_SECOND = Credential.fingerprint(bytes.fromhex("3299d7970000"))
_NEW_ENTRY = Credential.fingerprint(bytes.fromhex("3299e4a20002"))
_TUESDAY = WeeklyWindow(Weekday.TUESDAY, dt.time(20, 14), dt.time(21, 14))
_FRIDAY = WeeklyWindow(Weekday.FRIDAY, dt.time(20, 14), dt.time(21, 14))
_PERIOD = Period(dt.datetime(2026, 11, 25, 17, 29), dt.datetime(2027, 12, 25, 17, 29))  # noqa: DTZ001
_CLEAR_DONE = bytes.fromhex("70014004")
_ADD_DONE = bytes.fromhex("70014002")
_ALL_FEATURES = (LockFeature.FINGER_PRINT, LockFeature.CYCLIC_IC_OR_FINGER_PRINT)
_PERMANENT = "enroll, permanent"
_TIMED = "enroll, timed"
_NO_FINGER = "enroll, no finger placed (three attempts, identical)"
_AGAIN = "enroll the same finger again (already enrolled with a date range and a weekly window)"
_ERROR_0XE4 = bytes.fromhex("0600e4")


def _plain(operation: str, index: int, *, model: dict | None = None) -> bytes:
    """A captured RX plaintext of an operation, envelope included."""
    frames = [f for f in (model or SN478)[operation] if f["direction"] == "RX"]
    return bytes.fromhex(frames[index]["plaintext"])


_SHORT_REPLY_TIMEOUT = 0.3


@pytest.fixture(autouse=True)
def _short_reply_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fingerprint_manager_mod, "LOCK_REPLY_TIMEOUT", _SHORT_REPLY_TIMEOUT)


def _push_later(client: TTLockClient, fake: FakeBleakClient, plain: bytes, delay: float) -> None:
    """Deliver an unsolicited reply from the lock `delay` seconds from now."""
    push = _resp_frame(client.key, 0x54, plain)
    asyncio.get_running_loop().call_later(
        delay, fake._notify_cb, "notify-char", bytearray(push.build())
    )


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


def _enrollment(
    client: TTLockClient, operation: str = _PERMANENT, *, model: dict | None = None
) -> list:
    """What the lock sends after one command: ready, the touches, then the new id.

    Includes any unsolicited push the capture has in between.
    """
    return [_replies(client, *_rx(operation, model)[: _done_index(operation, model) + 1])]


def _validity_reply(operation: str, *, model: dict | None = None) -> bytes:
    """The lock's answer to the validity command that follows an enrollment."""
    return _rx(operation, model)[_done_index(operation, model) + 1]


def _rx(operation: str, model: dict | None) -> list[bytes]:
    frames = [f for f in (model or SN478)[operation] if f["direction"] == "RX"]
    return [bytes.fromhex(frame["plaintext"]) for frame in frames]


def _done_index(operation: str, model: dict | None) -> int:
    """Position of the reply that carries the new id: the only 9-byte reply of CMD 0x06."""
    return next(
        index
        for index, plain in enumerate(_rx(operation, model))
        if plain[0] == cmd.CMD_MANAGE_FINGERPRINT and len(plain) == 11
    )


def _refusal(command: int, error_code: int) -> bytes:
    return bytes([command, cmd.RESPONSE_FAILED, error_code])


def _sent(client: TTLockClient, fake: FakeBleakClient) -> list[tuple[int, bytes]]:
    aes = hex_key_to_bytes(client.key.aesKeyStr)
    frames = FrameReassembler().feed(b"".join(fake.written))
    return [(frame.command, aes_decrypt(frame.data, aes)) for frame in frames]


def _fingerprint_commands(client: TTLockClient, fake: FakeBleakClient) -> list[bytes]:
    """Every CMD 0x06 payload sent except the list queries (sub-op 6)."""
    return [
        data
        for command, data in _sent(client, fake)
        if command == cmd.CMD_MANAGE_FINGERPRINT and data[0] != 6
    ]


def _schedule_commands(client: TTLockClient, fake: FakeBleakClient) -> list[bytes]:
    return [data for command, data in _sent(client, fake) if command == cmd.CMD_WEEKLY_SCHEDULE]


class TestEnroll:
    async def test_permanent_sends_nothing_after_the_last_touch(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
            *_enrollment(client),
        ]
        credential = await client.fingerprints.enroll()
        assert credential == _FIRST
        assert _fingerprint_commands(client, fake) == [bytes.fromhex("0201")]
        assert fake.reply_for_next == []

    async def test_permanent_validity_object_is_the_same_as_none(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
            *_enrollment(client),
        ]
        assert await client.fingerprints.enroll(Permanent()) == _FIRST
        assert _fingerprint_commands(client, fake) == [bytes.fromhex("0201")]

    async def test_every_step_is_reported_with_its_touch_count(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
            *_enrollment(client),
        ]
        steps: list[FingerprintEnrollmentProgress] = []
        await client.fingerprints.enroll(on_progress=steps.append)
        waiting, touched, read = (
            FingerprintEnrollmentStep.WAITING_FOR_FINGER,
            FingerprintEnrollmentStep.TOUCH_RECORDED,
            FingerprintEnrollmentStep.FINGERPRINT_READ,
        )
        assert steps == [
            FingerprintEnrollmentProgress(waiting, 0, 4),
            FingerprintEnrollmentProgress(touched, 1, 4),
            FingerprintEnrollmentProgress(touched, 2, 4),
            FingerprintEnrollmentProgress(touched, 3, 4),
            FingerprintEnrollmentProgress(read, 4, 4),
        ]

    async def test_the_last_step_waits_for_the_validity(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
            *_enrollment(client, _TIMED),
            *_replies(client, _refusal(cmd.CMD_MANAGE_FINGERPRINT, 0x20)),
            *_admin(client),
            *_replies(client, _plain("delete one fingerprint", 0)),
        ]
        steps: list[FingerprintEnrollmentProgress] = []
        with pytest.raises(TTLockError, match="deleted again"):
            await client.fingerprints.enroll(_PERIOD, steps.append)
        assert FingerprintEnrollmentStep.FINGERPRINT_READ not in [step.step for step in steps]

    @pytest.mark.parametrize(
        ("capture", "identifier", "validity"),
        [
            (
                (SN478, _TIMED),
                _SECOND,
                Period(
                    dt.datetime(2026, 11, 25, 17, 29),  # noqa: DTZ001
                    dt.datetime(2027, 12, 25, 17, 29),  # noqa: DTZ001
                ),
            ),
            (
                (SN484, "enroll fingerprint, run 1"),
                Credential.fingerprint(bytes.fromhex("aabbcc01000a")),
                Period(
                    dt.datetime(2026, 11, 22, 19, 45),  # noqa: DTZ001
                    dt.datetime(2027, 11, 22, 19, 45),  # noqa: DTZ001
                ),
            ),
        ],
        ids=["SN478_PV53", "SN484_PV53"],
    )
    async def test_period_sends_the_dates_the_app_sent(
        self, patched_connect, capture, identifier, validity
    ) -> None:
        model, operation = capture
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
            *_enrollment(client, operation, model=model),
            *_replies(client, _validity_reply(operation, model=model)),
        ]
        credential = await client.fingerprints.enroll(validity)
        assert credential == identifier
        captured = [
            bytes.fromhex(f["plaintext"]) for f in model[operation] if f["direction"] == "TX"
        ]
        assert _fingerprint_commands(client, fake) == captured
        assert fake.reply_for_next == []

    async def test_weekly_sends_its_dates_then_its_windows(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        weekly = Weekly((_TUESDAY, _FRIDAY), _PERIOD.start, _PERIOD.end)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(*_ALL_FEATURES)),
            *_enrollment(client, _TIMED),
            *_replies(client, _validity_reply(_TIMED)),
            *_admin(client),
            *_replies(client, _CLEAR_DONE, _ADD_DONE, _ADD_DONE),
        ]
        await client.fingerprints.enroll(weekly)
        assert _fingerprint_commands(client, fake)[1] == bytes.fromhex(
            "053299d79700001a0b19111d1b0c19111d"
        )
        identifier = _SECOND.identifier.hex()
        assert _schedule_commands(client, fake) == [
            bytes.fromhex(f"040106{identifier}"),
            bytes.fromhex(f"020106{identifier}0102001" + "40e150e00000000"),
            bytes.fromhex(f"020106{identifier}0105001" + "40e150e00000000"),
        ]
        assert fake.reply_for_next == []

    async def test_unbounded_weekly_sends_the_permanent_dates(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(*_ALL_FEATURES)),
            *_enrollment(client, _TIMED),
            *_replies(client, _validity_reply(_TIMED)),
            *_admin(client),
            *_replies(client, _CLEAR_DONE, _ADD_DONE),
        ]
        await client.fingerprints.enroll(Weekly((_TUESDAY,)))
        assert _fingerprint_commands(client, fake)[1] == cmd.payload_fingerprint_modify(
            _SECOND.identifier, Permanent()
        )

    async def test_no_finger_placed_raises_a_typed_timeout(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
            _replies(client, _plain(_NO_FINGER, 0), _ERROR_0XE4),
        ]
        steps: list[FingerprintEnrollmentProgress] = []
        with pytest.raises(EnrollmentTimeoutError, match="Failed to enroll_fingerprint"):
            await client.fingerprints.enroll(on_progress=steps.append)
        assert [step.step for step in steps] == [FingerprintEnrollmentStep.WAITING_FOR_FINGER]
        assert _fingerprint_commands(client, fake) == [bytes.fromhex("0201")]

    async def test_the_lock_timeout_keeps_its_cause_and_is_a_reply_timeout(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
            _replies(client, _plain(_NO_FINGER, 0), _ERROR_0XE4),
        ]
        with pytest.raises(ReplyTimeoutError) as raised:
            await client.fingerprints.enroll()
        assert isinstance(raised.value, EnrollmentTimeoutError)
        assert isinstance(raised.value.__cause__, LockRejectedError)
        assert raised.value.__cause__.error_code == 0xE4

    async def test_the_lock_timeout_is_not_followed_by_a_delete(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
            _replies(client, _plain(_NO_FINGER, 0), _ERROR_0XE4),
        ]
        with pytest.raises(EnrollmentTimeoutError):
            await client.fingerprints.enroll(Period(_PERIOD.start, _PERIOD.end))
        assert all(data[0] == 2 for data in _fingerprint_commands(client, fake))

    async def test_error_0xe4_outside_an_enrollment_stays_a_plain_rejection(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT), _ERROR_0XE4),
        ]
        with pytest.raises(LockRejectedError, match="delete_fingerprint") as raised:
            await client.fingerprints.delete(_FIRST)
        assert not isinstance(raised.value, EnrollmentTimeoutError)

    async def test_a_link_that_goes_silent_after_ready_is_a_typed_timeout(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
            _replies(client, _plain(_NO_FINGER, 0)),
        ]
        started = time.monotonic()
        with pytest.raises(EnrollmentTimeoutError, match=r"within 0\.3 s.*still be in add mode"):
            await client.fingerprints.enroll(timeout=0.05)
        assert time.monotonic() - started >= 0.3

    async def test_a_link_dropped_after_ready_ends_the_wait_at_once(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
            _replies(client, _plain(_NO_FINGER, 0)),
        ]

        def drop() -> None:
            fake.is_connected = False
            client._transport._on_disconnected(fake)

        loop = asyncio.get_running_loop()
        started = time.monotonic()
        with pytest.raises(EnrollmentTimeoutError, match="dropped the link") as raised:
            await client.fingerprints.enroll(
                on_progress=lambda _progress: loop.call_soon(drop), timeout=0.05
            )
        assert time.monotonic() - started < _SHORT_REPLY_TIMEOUT
        assert isinstance(raised.value.__cause__, LinkLostError)

    async def test_a_lock_that_never_answers_is_a_plain_reply_timeout(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
        ]
        with pytest.raises(ReplyTimeoutError) as raised:
            await client.fingerprints.enroll(timeout=0.05)
        assert not isinstance(raised.value, EnrollmentTimeoutError)

    @pytest.mark.usefixtures("_short_reply_timeout")
    async def test_each_reply_restarts_the_reply_timeout(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        gap = _SHORT_REPLY_TIMEOUT / 2
        touches_and_id = [_plain(_PERMANENT, index) for index in range(1, 5)]
        assert gap < _SHORT_REPLY_TIMEOUT < gap * len(touches_and_id)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
            _replies(client, _plain(_PERMANENT, 0)),
        ]
        for position, plain in enumerate(touches_and_id, start=1):
            _push_later(client, fake, plain, gap * position)
        started = time.monotonic()
        credential = await client.fingerprints.enroll(timeout=gap * 2 * len(touches_and_id))
        assert time.monotonic() - started > _SHORT_REPLY_TIMEOUT
        assert credential == _FIRST

    @pytest.mark.parametrize(
        "reply",
        [bytes.fromhex("06016402"), bytes.fromhex("0601640209"), bytes.fromhex("06016403")],
    )
    async def test_an_unexpected_reply_is_an_error(self, patched_connect, reply) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT), reply),
        ]
        with pytest.raises(TTLockError, match=r"Failed to enroll_fingerprint: .*unexpected reply"):
            await client.fingerprints.enroll()

    async def test_a_full_lock_raises_storage_full(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(
                client,
                _features(LockFeature.FINGER_PRINT),
                _refusal(cmd.CMD_MANAGE_FINGERPRINT, 0x16),
            ),
        ]
        with pytest.raises(StorageFullError, match="enroll_fingerprint"):
            await client.fingerprints.enroll()

    async def test_re_enrolling_a_known_finger_returns_the_new_id(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
            *_enrollment(client, _AGAIN),
        ]
        credential = await client.fingerprints.enroll()
        assert credential == _NEW_ENTRY
        assert credential != _SECOND
        assert _fingerprint_commands(client, fake) == [bytes.fromhex("0201")]

    async def test_a_rollback_after_a_re_enrollment_deletes_only_the_new_id(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
            *_enrollment(client, _AGAIN),
            *_replies(client, _refusal(cmd.CMD_MANAGE_FINGERPRINT, 0x20)),
            *_admin(client),
            *_replies(client, _plain("delete one fingerprint", 0)),
        ]
        with pytest.raises(TTLockError, match="the new fingerprint was deleted again"):
            await client.fingerprints.enroll(_PERIOD)
        assert _fingerprint_commands(client, fake)[-1] == cmd.payload_fingerprint_delete(
            _NEW_ENTRY.identifier
        )

    async def test_a_refused_validity_deletes_the_fingerprint_again(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
            *_enrollment(client, _TIMED),
            *_replies(client, _refusal(cmd.CMD_MANAGE_FINGERPRINT, 0x20)),
            *_admin(client),
            *_replies(client, _plain("delete one fingerprint", 0)),
        ]
        with pytest.raises(TTLockError, match="the new fingerprint was deleted again") as raised:
            await client.fingerprints.enroll(_PERIOD)
        assert "0x20" in str(raised.value)
        assert raised.value.__cause__ is not None
        assert _fingerprint_commands(client, fake)[-1] == bytes.fromhex(
            "033299d79700 00".replace(" ", "")
        )
        assert fake.reply_for_next == []

    async def test_a_failed_weekly_step_deletes_the_fingerprint_again(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(*_ALL_FEATURES)),
            *_enrollment(client, _TIMED),
            *_replies(client, _validity_reply(_TIMED)),
            *_admin(client),
            *_replies(client, _CLEAR_DONE, _refusal(cmd.CMD_WEEKLY_SCHEDULE, 0x20)),
            *_admin(client),
            *_replies(client, _plain("delete one fingerprint", 0)),
        ]
        with pytest.raises(TTLockError, match="deleted again") as raised:
            await client.fingerprints.enroll(Weekly((_TUESDAY,)))
        assert "windows cleared, only 0 of 1 written" in str(raised.value)
        assert _fingerprint_commands(client, fake)[-1] == cmd.payload_fingerprint_delete(
            _SECOND.identifier
        )

    async def test_a_failed_rollback_is_reported_with_the_original_error(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
            *_enrollment(client, _TIMED),
            *_replies(client, _refusal(cmd.CMD_MANAGE_FINGERPRINT, 0x20)),
            *_admin(client),
            *_replies(client, _refusal(cmd.CMD_MANAGE_FINGERPRINT, 0x1A)),
        ]
        with pytest.raises(TTLockError) as raised:
            await client.fingerprints.enroll(_PERIOD)
        message = str(raised.value)
        assert "0x20" in message
        assert "deleting the new fingerprint also failed" in message
        assert "0x1a" in message
        assert "permanent, unrestricted" in message
        assert fake.reply_for_next == []

    async def test_a_weekly_fingerprint_needs_the_cyclic_feature_before_anything_is_sent(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
        ]
        with pytest.raises(UnsupportedFeatureError, match="CYCLIC_IC_OR_FINGER_PRINT"):
            await client.fingerprints.enroll(Weekly((_TUESDAY,)))
        assert _fingerprint_commands(client, fake) == []

    async def test_single_use_is_refused_before_connecting(self) -> None:
        client = TTLockClient(make_virtual_key())
        single = SingleUse(dt.datetime(2026, 1, 1), dt.datetime(2026, 1, 2))  # noqa: DTZ001
        with pytest.raises(ValueError, match="single-use"):
            await client.fingerprints.enroll(single)


class TestEnrollPastTheDeadline:
    """The lock keeps add mode open after the caller's timeout (SN478_PV53)."""

    async def test_a_finger_completing_after_the_deadline_is_deleted_and_reported(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
            _replies(client, _plain(_PERMANENT, 0)),
            *_replies(client, _plain("delete one fingerprint", 0)),
        ]
        _push_later(client, fake, _plain(_PERMANENT, 4), 0.15)
        with pytest.raises(FingerprintEnrolledLateError, match=r"after the 0\.05 s") as raised:
            await client.fingerprints.enroll(timeout=0.05)
        assert raised.value.removed
        assert "removed again" in str(raised.value)
        assert _fingerprint_commands(client, fake) == [
            bytes.fromhex("0201"),
            cmd.payload_fingerprint_delete(_FIRST.identifier),
        ]
        assert fake.reply_for_next == []

    async def test_a_dated_late_enrollment_is_deleted_without_applying_the_dates(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(*_ALL_FEATURES)),
            _replies(client, _plain(_PERMANENT, 0)),
            *_replies(client, _plain("delete one fingerprint", 0)),
        ]
        _push_later(client, fake, _plain(_PERMANENT, 4), 0.15)
        with pytest.raises(FingerprintEnrolledLateError) as raised:
            await client.fingerprints.enroll(Weekly((_TUESDAY,)), timeout=0.05)
        assert raised.value.removed
        assert [data[0] for data in _fingerprint_commands(client, fake)] == [2, 3]
        assert _schedule_commands(client, fake) == []

    async def test_a_late_fingerprint_that_cannot_be_deleted_says_it_may_still_work(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
            _replies(client, _plain(_PERMANENT, 0)),
            *_replies(client, _refusal(cmd.CMD_MANAGE_FINGERPRINT, 0x1A)),
        ]
        _push_later(client, fake, _plain(_PERMANENT, 4), 0.15)
        with pytest.raises(FingerprintEnrolledLateError, match="may still open the lock") as raised:
            await client.fingerprints.enroll(timeout=0.05)
        assert not raised.value.removed
        assert "0x1a" in str(raised.value)
        assert _FIRST.identifier.hex() not in str(raised.value)

    async def test_error_0xe4_after_the_deadline_is_the_usual_timeout(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
            _replies(client, _plain(_NO_FINGER, 0)),
        ]
        _push_later(client, fake, _ERROR_0XE4, 0.15)
        with pytest.raises(EnrollmentTimeoutError) as raised:
            await client.fingerprints.enroll(timeout=0.05)
        assert not isinstance(raised.value, FingerprintEnrolledLateError)
        assert _fingerprint_commands(client, fake) == [bytes.fromhex("0201")]

    async def test_progress_keeps_arriving_past_the_deadline(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
            _replies(client, _plain(_PERMANENT, 0)),
            *_replies(client, _plain("delete one fingerprint", 0)),
        ]
        for index, delay in ((1, 0.1), (2, 0.15), (3, 0.2), (4, 0.25)):
            _push_later(client, fake, _plain(_PERMANENT, index), delay)
        steps: list[FingerprintEnrollmentProgress] = []
        with pytest.raises(FingerprintEnrolledLateError):
            await client.fingerprints.enroll(on_progress=steps.append, timeout=0.05)
        assert [step.touches_recorded for step in steps] == [0, 1, 2, 3]
        assert fake.reply_for_next == []

    async def test_a_finger_completing_inside_the_deadline_is_not_late(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
            _replies(client, _plain(_PERMANENT, 0)),
        ]
        _push_later(client, fake, _plain(_PERMANENT, 4), 0.05)
        assert await client.fingerprints.enroll(timeout=0.5) == _FIRST
        assert _fingerprint_commands(client, fake) == [bytes.fromhex("0201")]

    def test_the_late_error_survives_pickling(self) -> None:
        error = pickle.loads(pickle.dumps(FingerprintEnrolledLateError("late", removed=True)))  # noqa: S301
        assert (str(error), error.removed) == ("late", True)
        assert isinstance(error, TTLockError)


class TestModify:
    async def test_period_matches_the_capture_and_clears_the_windows(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        identifier = bytes.fromhex("aabbcc030009")
        validity = Period(dt.datetime(2026, 9, 1, 1, 0), dt.datetime(2027, 9, 2, 0, 59))  # noqa: DTZ001
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(*_ALL_FEATURES), bytes.fromhex("06014005")),
            *_admin(client),
            *_replies(client, _CLEAR_DONE),
        ]
        await client.fingerprints.modify(Credential.fingerprint(identifier), validity)
        assert _fingerprint_commands(client, fake) == [
            bytes.fromhex("05aabbcc0300091a090101001b0902003b")
        ]
        assert _schedule_commands(client, fake) == [bytes.fromhex("040106aabbcc030009")]
        assert fake.reply_for_next == []

    async def test_weekly_matches_the_capture(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        identifier = bytes.fromhex("aabbcc030009")
        weekly = Weekly(
            (
                WeeklyWindow(Weekday.TUESDAY, dt.time(21, 18), dt.time(23, 18)),
                WeeklyWindow(Weekday.FRIDAY, dt.time(21, 18), dt.time(23, 18)),
            ),
            dt.datetime(2026, 9, 1, 1, 0),  # noqa: DTZ001
            dt.datetime(2027, 9, 2, 0, 59),  # noqa: DTZ001
        )
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(*_ALL_FEATURES), bytes.fromhex("06014005")),
            *_admin(client),
            *_replies(client, _CLEAR_DONE, _ADD_DONE, _ADD_DONE),
        ]
        await client.fingerprints.modify(Credential.fingerprint(identifier), weekly)
        assert _fingerprint_commands(client, fake) == [
            bytes.fromhex("05aabbcc0300091a090101001b0902003b")
        ]
        assert _schedule_commands(client, fake) == [
            bytes.fromhex("040106aabbcc030009"),
            bytes.fromhex("020106aabbcc0300090102001512171200000000"),
            bytes.fromhex("020106aabbcc0300090105001512171200000000"),
        ]

    async def test_permanent_sends_the_permanent_dates(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(*_ALL_FEATURES), bytes.fromhex("06014005")),
            *_admin(client),
            *_replies(client, _CLEAR_DONE),
        ]
        await client.fingerprints.modify(_FIRST, Permanent())
        assert _fingerprint_commands(client, fake) == [
            bytes([5]) + _FIRST.identifier + cmd.START_DATE_SENTINEL + cmd.END_DATE_SENTINEL
        ]

    async def test_a_lock_without_windows_skips_clearing_them(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT), bytes.fromhex("06014005")),
            *_admin(client),
        ]
        await client.fingerprints.modify(_FIRST, _PERIOD)
        assert _schedule_commands(client, fake) == []
        assert fake.reply_for_next == []

    async def test_a_missing_fingerprint_raises_not_found(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(
                client,
                _features(LockFeature.FINGER_PRINT),
                _refusal(cmd.CMD_MANAGE_FINGERPRINT, 0x1A),
            ),
        ]
        with pytest.raises(CredentialNotFoundError, match="modify_fingerprint"):
            await client.fingerprints.modify(_FIRST, _PERIOD)
        assert _schedule_commands(client, fake) == []

    async def test_a_failed_window_write_keeps_the_new_dates_and_says_so(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(*_ALL_FEATURES), bytes.fromhex("06014005")),
            *_admin(client),
            *_replies(client, _CLEAR_DONE, _refusal(cmd.CMD_WEEKLY_SCHEDULE, 0x20)),
        ]
        with pytest.raises(TTLockError, match="windows cleared, only 0 of 1 written"):
            await client.fingerprints.modify(_FIRST, Weekly((_TUESDAY,)))
        assert len(_fingerprint_commands(client, fake)) == 1

    async def test_a_weekly_validity_needs_the_cyclic_feature(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
        ]
        with pytest.raises(UnsupportedFeatureError, match="CYCLIC_IC_OR_FINGER_PRINT"):
            await client.fingerprints.modify(_FIRST, Weekly((_TUESDAY,)))
        assert _fingerprint_commands(client, fake) == []


class TestDeleteAndClear:
    @pytest.mark.parametrize(
        ("model", "operation", "identifier"),
        [
            (SN478, "delete one fingerprint", "3299e2f60001"),
            (SN484, "delete fingerprint, run 1", "aabbcc01000a"),
        ],
        ids=["SN478_PV53", "SN484_PV53"],
    )
    async def test_delete_one_matches_the_capture(
        self, patched_connect, model, operation, identifier
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(
                client,
                _features(LockFeature.FINGER_PRINT),
                _plain(operation, 0, model=model),
            ),
        ]
        await client.fingerprints.delete(Credential.fingerprint(bytes.fromhex(identifier)))
        assert _fingerprint_commands(client, fake) == [bytes.fromhex("03" + identifier)]

    async def test_delete_a_missing_fingerprint_raises_not_found(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(
                client,
                _features(LockFeature.FINGER_PRINT),
                _refusal(cmd.CMD_MANAGE_FINGERPRINT, 0x1A),
            ),
        ]
        with pytest.raises(CredentialNotFoundError, match="delete_fingerprint") as raised:
            await client.fingerprints.delete(_FIRST)
        assert raised.value.error_code == 0x1A

    async def test_clear_matches_the_capture(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(
                client,
                _features(LockFeature.FINGER_PRINT),
                _plain("clear all fingerprints (app: reset)", 0),
            ),
        ]
        await client.fingerprints.clear()
        assert _fingerprint_commands(client, fake) == [bytes.fromhex("04")]

    @pytest.mark.parametrize(
        "call",
        [
            lambda fingerprints: fingerprints.enroll(),
            lambda fingerprints: fingerprints.modify(_FIRST, Permanent()),
            lambda fingerprints: fingerprints.delete(_FIRST),
            lambda fingerprints: fingerprints.clear(),
        ],
        ids=["enroll", "modify", "delete", "clear"],
    )
    async def test_every_write_needs_the_fingerprint_feature(self, patched_connect, call) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.IC)),
        ]
        with pytest.raises(UnsupportedFeatureError, match="FINGER_PRINT"):
            await call(client.fingerprints)
        assert _fingerprint_commands(client, fake) == []

    @pytest.mark.parametrize(
        "call",
        [
            lambda fingerprints, other: fingerprints.modify(other, Permanent()),
            lambda fingerprints, other: fingerprints.delete(other),
        ],
        ids=["modify", "delete"],
    )
    async def test_a_card_is_refused_before_connecting(self, call) -> None:
        client = TTLockClient(make_virtual_key())
        with pytest.raises(ValueError, match="expected a fingerprint"):
            await call(client.fingerprints, Credential.card(0x55667788))

    async def test_a_listed_fingerprint_is_addressed_by_its_id_and_slot(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        listed = FingerprintEntry(
            fingerprint_id=bytes.fromhex("3299e4a2"), slot=2, start_date=None, end_date=None
        )
        fake.reply_for_next = [
            *_admin(client),
            *_replies(
                client, _features(LockFeature.FINGER_PRINT), _plain("delete one fingerprint", 0)
            ),
        ]
        await client.fingerprints.delete(Credential.of(listed))
        assert _fingerprint_commands(client, fake) == [bytes.fromhex("033299e4a20002")]


def _entry_plain(
    identifier: bytes,
    position: int,
    start: bytes = cmd.START_DATE_SENTINEL,
    end: bytes = cmd.END_DATE_SENTINEL,
) -> bytes:
    data = bytes([0x64, 0x06]) + position.to_bytes(2, "big") + identifier
    return bytes([cmd.CMD_MANAGE_FINGERPRINT, cmd.RESPONSE_SUCCESS]) + data + start + end


def _end_plain() -> bytes:
    return bytes([cmd.CMD_MANAGE_FINGERPRINT, cmd.RESPONSE_SUCCESS]) + bytes.fromhex("6406ffff")


class TestList:
    async def test_without_windows_asks_nothing_more(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _entry_plain(_FIRST.identifier, 1), _end_plain()),
        ]
        entries = await client.fingerprints.list(include_weekly_windows=False)
        assert [entry.identifier for entry in entries] == [_FIRST.identifier]
        assert entries[0].weekly_windows is None
        assert _schedule_commands(client, fake) == []

    async def test_get_fingerprints_delegates_without_windows(self, patched_connect) -> None:
        client, _fake = await _connected(patched_connect)
        client.fingerprints.list = AsyncMock(return_value=[])
        assert await client.get_fingerprints() == []
        client.fingerprints.list.assert_awaited_once_with(include_weekly_windows=False)

    async def test_includes_each_fingerprints_windows(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(
                client,
                _entry_plain(_FIRST.identifier, 1),
                _entry_plain(_SECOND.identifier, 2),
                _end_plain(),
            ),
        ]
        windows = (_TUESDAY,)
        client.weekly_schedules.get = AsyncMock(side_effect=[windows, ()])
        entries = await client.fingerprints.list()
        assert [entry.weekly_windows for entry in entries] == [windows, ()]
        asked = [call.args[0] for call in client.weekly_schedules.get.await_args_list]
        assert asked == [Credential.of(entry) for entry in entries]

    async def test_a_lock_without_windows_reads_none_and_stops_asking(
        self, patched_connect
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(
                client,
                _entry_plain(_FIRST.identifier, 1),
                _entry_plain(_SECOND.identifier, 2),
                _end_plain(),
            ),
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
        ]
        entries = await client.fingerprints.list()
        assert [entry.weekly_windows for entry in entries] == [(), ()]
        assert fake.reply_for_next == []

    async def test_an_empty_lock(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [*_admin(client), *_replies(client, _end_plain())]
        assert await client.fingerprints.list() == []

    async def test_listing_needs_no_fingerprint_feature(self, patched_connect) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [*_admin(client), *_replies(client, _end_plain())]
        await client.fingerprints.list(include_weekly_windows=False)
        assert all(command != cmd.CMD_SEARCH_DEVICE_FEATURE for command, _ in _sent(client, fake))


class TestPrivacy:
    @staticmethod
    def _secrets(credential: Credential) -> tuple[str, ...]:
        return (
            credential.identifier.hex(),
            credential.identifier[:4].hex(),
            str(int.from_bytes(credential.identifier, "big")),
        )

    async def test_ids_stay_out_of_logs_reprs_and_errors(self, patched_connect, caplog) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(*_ALL_FEATURES)),
            *_enrollment(client, _TIMED),
            *_replies(client, _refusal(cmd.CMD_MANAGE_FINGERPRINT, 0x20)),
            *_admin(client),
            *_replies(client, _refusal(cmd.CMD_MANAGE_FINGERPRINT, 0x1A)),
        ]
        with caplog.at_level(logging.DEBUG), pytest.raises(TTLockError) as raised:
            await client.fingerprints.enroll(_PERIOD)
        text = caplog.text + "".join(traceback.format_exception(raised.value))
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _entry_plain(_SECOND.identifier, 1), _end_plain()),
        ]
        with caplog.at_level(logging.DEBUG):
            (entry,) = await client.get_fingerprints()
        text += caplog.text + repr(entry) + repr(Credential.of(entry)) + repr(client.fingerprints)
        for secret in self._secrets(_SECOND):
            assert secret not in text

    async def test_a_successful_enrollment_logs_no_id(self, patched_connect, caplog) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
            *_enrollment(client),
        ]
        with caplog.at_level(logging.DEBUG):
            credential = await client.fingerprints.enroll()
        text = caplog.text + repr(credential)
        for secret in self._secrets(_FIRST):
            assert secret not in text

    async def test_the_listing_does_not_log_the_reply_bytes(self, patched_connect, caplog) -> None:
        client, fake = await _connected(patched_connect)
        reply = _entry_plain(_FIRST.identifier, 1)
        fake.reply_for_next = [*_admin(client), *_replies(client, reply, _end_plain())]
        with caplog.at_level(logging.DEBUG):
            await client.get_fingerprints()
        assert reply.hex() not in caplog.text
        for secret in self._secrets(_FIRST):
            assert secret not in caplog.text

    async def test_timeouts_and_missing_fingerprints_stay_private(
        self, patched_connect, caplog
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, _features(LockFeature.FINGER_PRINT)),
            _replies(client, _plain(_NO_FINGER, 0), _ERROR_0XE4),
        ]
        with caplog.at_level(logging.DEBUG):
            with pytest.raises(EnrollmentTimeoutError) as timeout:
                await client.fingerprints.enroll()
            fake.reply_for_next = [
                *_admin(client),
                *_replies(client, _refusal(cmd.CMD_MANAGE_FINGERPRINT, 0x1A)),
            ]
            with pytest.raises(CredentialNotFoundError) as missing:
                await client.fingerprints.delete(_FIRST)
        text = caplog.text + "".join(
            traceback.format_exception(timeout.value) + traceback.format_exception(missing.value)
        )
        for secret in self._secrets(_FIRST):
            assert secret not in text

    @pytest.mark.parametrize(
        "reply",
        [
            bytes.fromhex("0601640206"),
            bytes.fromhex("06016402013299d6ae"),
            _entry_plain(_FIRST.identifier, 1)[:-1],
            bytes([cmd.CMD_MANAGE_FINGERPRINT, cmd.RESPONSE_FAILED, 0x02]) + _FIRST.identifier,
        ],
        ids=["short enrollment", "truncated id", "truncated listing", "rejected listing"],
    )
    async def test_malformed_replies_do_not_echo_the_bytes(
        self, patched_connect, caplog, reply
    ) -> None:
        client, fake = await _connected(patched_connect)
        fake.reply_for_next = [
            *_admin(client),
            *_replies(client, reply),
        ]
        with caplog.at_level(logging.DEBUG), pytest.raises(TTLockError) as raised:
            await client.get_fingerprints()
        text = caplog.text + "".join(traceback.format_exception(raised.value))
        assert reply.hex() not in text
        for secret in self._secrets(_FIRST):
            assert secret not in text


def test_fingerprint_entry_repr_hides_the_id_and_reports_windows() -> None:
    entry = FingerprintEntry(
        fingerprint_id=_FIRST.identifier[:4],
        slot=0,
        start_date=None,
        end_date=None,
        weekly_windows=(_TUESDAY,),
    )
    assert _FIRST.identifier.hex() not in repr(entry)
    assert _FIRST.identifier[:4].hex() not in repr(entry)
    assert entry.weekly_windows == (_TUESDAY,)
