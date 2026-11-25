"""CMD 0x06 fingerprint payloads and the enrollment reply parser, against captured bytes.

`tests/fixtures/fingerprints/` holds the official app managing fingerprints on
two lock models: `fixture_fingerprints_phase4.json` (SN478_PV53, firmware
6.4.43.240529) and `fixture_fingerprints_sn484.json` (SN484_PV53, firmware
6.5.15.240522).
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from ttlock_ble import (
    FingerprintEnrollmentProgress,
    FingerprintEnrollmentStep,
    Period,
    Permanent,
    SingleUse,
    Weekday,
    Weekly,
    WeeklyWindow,
)
from ttlock_ble import commands as cmd

_FIXTURES = Path(__file__).parent / "fixtures" / "fingerprints"


def _load(name: str) -> dict[str, list[dict]]:
    fixture = json.loads((_FIXTURES / name).read_text())
    return {operation["operation"]: operation["frames"] for operation in fixture["operations"]}


SN478 = _load("fixture_fingerprints_phase4.json")
SN484 = _load("fixture_fingerprints_sn484.json")
MODELS = {"SN478_PV53": SN478, "SN484_PV53": SN484}
_PERMANENT_DATES = cmd.START_DATE_SENTINEL + cmd.END_DATE_SENTINEL
_AGAIN = "enroll the same finger again (already enrolled with a date range and a weekly window)"
_MONDAY = WeeklyWindow(Weekday.MONDAY, dt.time(8), dt.time(9))
_WAITING = FingerprintEnrollmentStep.WAITING_FOR_FINGER
_TOUCH = FingerprintEnrollmentStep.TOUCH_RECORDED


def sent(operations: dict[str, list[dict]], operation: str) -> list[bytes]:
    return [
        bytes.fromhex(frame["plaintext"])
        for frame in operations[operation]
        if frame["direction"] == "TX"
    ]


def received(operations: dict[str, list[dict]], operation: str) -> list[bytes]:
    """Reply data after the `[0x06][status]` envelope, starting with the battery byte."""
    plains = [
        bytes.fromhex(frame["plaintext"])
        for frame in operations[operation]
        if frame["direction"] == "RX"
    ]
    return [cmd.parse_response_status(plain)[2] for plain in plains if plain[0] == 0x06]


def _period(start: tuple[int, ...], end: tuple[int, ...]) -> Period:
    return Period(dt.datetime(*start), dt.datetime(*end))  # noqa: DTZ001 -- lock-local clock


class TestCapturedPayloads:
    @pytest.mark.parametrize(
        ("operations", "operation"),
        [
            (SN478, "enroll, permanent"),
            (SN478, "enroll, timed"),
            (SN478, "enroll, no finger placed (three attempts, identical)"),
            (SN478, _AGAIN),
            (SN484, "enroll fingerprint, run 1"),
            (SN484, "enroll fingerprint, run 2"),
        ],
    )
    def test_enroll_enters_add_mode_and_never_clears_first(self, operations, operation) -> None:
        assert sent(operations, operation)[0] == cmd.payload_fingerprint_enroll()
        assert cmd.payload_fingerprint_enroll() == bytes.fromhex("0201")
        assert bytes.fromhex("04") not in sent(operations, operation)

    def test_timed_enrollment_validity_on_sn478(self) -> None:
        validity = _period((2026, 11, 25, 17, 29), (2027, 12, 25, 17, 29))
        identifier = bytes.fromhex("3299d7970000")
        assert sent(SN478, "enroll, timed")[1] == cmd.payload_fingerprint_modify(
            identifier, validity
        )

    @pytest.mark.parametrize(
        ("operation", "identifier", "validity"),
        [
            (
                "enroll fingerprint, run 1",
                "aabbcc01000a",
                _period((2026, 11, 22, 19, 45), (2027, 11, 22, 19, 45)),
            ),
            (
                "enroll fingerprint, run 2",
                "aabbcc02000a",
                _period((2026, 11, 22, 19, 59), (2027, 11, 22, 19, 59)),
            ),
        ],
    )
    def test_timed_enrollment_validity_on_sn484(self, operation, identifier, validity) -> None:
        assert sent(SN484, operation)[1] == cmd.payload_fingerprint_modify(
            bytes.fromhex(identifier), validity
        )

    def test_editing_a_validity_on_sn484(self) -> None:
        validity = _period((2026, 9, 1, 1, 0), (2027, 9, 2, 0, 59))
        sent_payload = sent(SN484, "edit a fingerprint validity")[0]
        assert sent_payload == cmd.payload_fingerprint_modify(
            bytes.fromhex("aabbcc030009"), validity
        )

    def test_a_weekly_validity_sends_its_dates_like_a_period(self) -> None:
        start, end = dt.datetime(2026, 9, 1, 1), dt.datetime(2027, 9, 2, 0, 59)  # noqa: DTZ001
        identifier = bytes.fromhex("aabbcc030009")
        assert cmd.payload_fingerprint_modify(
            identifier, Weekly((_MONDAY,), start, end)
        ) == cmd.payload_fingerprint_modify(identifier, Period(start, end))

    @pytest.mark.parametrize("validity", [Permanent(), Weekly((_MONDAY,))])
    def test_a_permanent_validity_sends_the_permanent_dates(self, validity) -> None:
        identifier = bytes.fromhex("aabbcc030009")
        assert (
            cmd.payload_fingerprint_modify(identifier, validity)
            == bytes([5]) + identifier + _PERMANENT_DATES
        )

    @pytest.mark.parametrize(
        ("operations", "operation", "identifier"),
        [
            (SN478, "delete one fingerprint", "3299e2f60001"),
            (SN484, "delete fingerprint, run 1", "aabbcc01000a"),
            (SN484, "delete fingerprint, run 2", "aabbcc02000a"),
        ],
    )
    def test_delete_one(self, operations, operation, identifier) -> None:
        assert sent(operations, operation) == [
            cmd.payload_fingerprint_delete(bytes.fromhex(identifier))
        ]

    def test_clear_all(self) -> None:
        assert sent(SN478, "clear all fingerprints (app: reset)") == [
            cmd.payload_fingerprint_clear()
        ]
        assert cmd.payload_fingerprint_clear() == bytes([4])

    def test_single_use_is_refused(self) -> None:
        single = SingleUse(dt.datetime(2026, 1, 1), dt.datetime(2026, 1, 2))  # noqa: DTZ001
        with pytest.raises(ValueError, match="fingerprint cannot be single-use"):
            cmd.check_fingerprint_validity(single)
        with pytest.raises(ValueError, match="single-use"):
            cmd.payload_fingerprint_modify(bytes(6), single)

    @pytest.mark.parametrize("identifier", [b"", bytes(4), bytes(5), bytes(7)])
    def test_an_id_that_is_not_six_bytes_is_refused(self, identifier) -> None:
        with pytest.raises(ValueError, match="6 bytes"):
            cmd.payload_fingerprint_delete(identifier)
        with pytest.raises(ValueError, match="6 bytes"):
            cmd.payload_fingerprint_modify(identifier, Permanent())


class TestCapturedReplies:
    @pytest.mark.parametrize(
        ("operations", "operation"),
        [
            (SN478, "enroll, permanent"),
            (SN478, "enroll, timed"),
            (SN478, _AGAIN),
            (SN484, "enroll fingerprint, run 1"),
            (SN484, "enroll fingerprint, run 2"),
        ],
    )
    def test_the_captured_progress_sequence_is_accepted(self, operations, operation) -> None:
        replies = received(operations, operation)[:5]
        parsed = [cmd.parse_fingerprint_enrollment_reply(data) for data in replies]
        assert parsed[:4] == [
            FingerprintEnrollmentProgress(_WAITING, 0, 4),
            FingerprintEnrollmentProgress(_TOUCH, 1, 4),
            FingerprintEnrollmentProgress(_TOUCH, 2, 4),
            FingerprintEnrollmentProgress(_TOUCH, 3, 4),
        ]
        assert isinstance(parsed[4], bytes)
        assert len(parsed[4]) == 6

    @pytest.mark.parametrize(
        ("operations", "operation", "identifier"),
        [
            (SN478, "enroll, permanent", "3299d6ae0000"),
            (SN478, "enroll, timed", "3299d7970000"),
            (SN484, "enroll fingerprint, run 1", "aabbcc01000a"),
            (SN484, "enroll fingerprint, run 2", "aabbcc02000a"),
        ],
    )
    def test_the_finished_enrollment_carries_the_id_and_the_slot(
        self, operations, operation, identifier
    ) -> None:
        assert cmd.parse_fingerprint_enrollment_reply(
            received(operations, operation)[4]
        ) == bytes.fromhex(identifier)

    def test_re_enrolling_a_known_finger_reports_a_new_id(self) -> None:
        operation = _AGAIN
        identifier = cmd.parse_fingerprint_enrollment_reply(received(SN478, operation)[4])
        assert identifier == bytes.fromhex("3299e4a20002")
        assert identifier != bytes.fromhex("3299d7970000")

    def test_the_lock_own_timeout_is_a_failure_with_error_0xe4(self) -> None:
        frames = SN478["enroll, no finger placed (three attempts, identical)"]
        status = cmd.parse_response_status(bytes.fromhex(frames[2]["plaintext"]))
        assert status == (0x06, cmd.RESPONSE_FAILED, bytes([0xE4]))

    @pytest.mark.parametrize(
        "reply",
        [
            b"",
            bytes.fromhex("06"),
            bytes.fromhex("640202"),
            bytes.fromhex("64020200"),
            bytes.fromhex("64020301"),
            bytes.fromhex("6402030004"),
            bytes.fromhex("6402030504"),
            bytes.fromhex("640204"),
            bytes.fromhex("64020101020304"),
            bytes.fromhex("6403020204"),
        ],
    )
    def test_anything_else_is_refused_without_echoing_it(self, reply) -> None:
        with pytest.raises(ValueError, match="unexpected reply") as raised:
            cmd.parse_fingerprint_enrollment_reply(reply)
        assert not reply or reply.hex() not in str(raised.value)
