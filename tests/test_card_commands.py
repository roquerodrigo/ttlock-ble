"""CMD 0x05 card payloads and the enrollment reply parser, against captured bytes.

`tests/fixtures/cards/fixture_cards_phase3.json` holds sanitized captures of
the official app managing IC cards on a lock of model SN484_PV53 (firmware
6.5.15.240522); card ids are the placeholders 0x11223344 and 0x55667788.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from ttlock_ble import Credential, Period, Permanent, SingleUse, Weekday, Weekly, WeeklyWindow
from ttlock_ble import commands as cmd

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "cards" / "fixture_cards_phase3.json").read_text()
)
OPERATIONS = {operation["operation"]: operation["frames"] for operation in FIXTURE["operations"]}
FIRST_CARD = Credential.card(0x55667788).identifier
SECOND_CARD = Credential.card(0x11223344).identifier
_PERMANENT_DATES = cmd.START_DATE_SENTINEL + cmd.END_DATE_SENTINEL
_MONDAY = WeeklyWindow(Weekday.MONDAY, dt.time(8), dt.time(9))


def _sent(operation: str) -> list[bytes]:
    return [bytes.fromhex(f["plaintext"]) for f in OPERATIONS[operation] if f["direction"] == "TX"]


def _received(operation: str) -> list[bytes]:
    """Reply data after the `[0x05][status]` envelope, starting with the battery byte."""
    plains = [
        bytes.fromhex(f["plaintext"]) for f in OPERATIONS[operation] if f["direction"] == "RX"
    ]
    return [cmd.parse_response_status(plain)[2] for plain in plains]


def _period(start: tuple[int, ...], end: tuple[int, ...]) -> Period:
    return Period(dt.datetime(*start), dt.datetime(*end))  # noqa: DTZ001 -- lock-local clock


class TestCapturedPayloads:
    def test_enroll_enters_add_mode(self) -> None:
        for operation in (
            "enroll by tap, permanent",
            "enroll by tap, no card presented",
            "enroll by tap, second card, permanent",
            "enroll by tap, timed",
        ):
            assert _sent(operation)[0] == cmd.payload_card_enroll() == bytes.fromhex("0201")

    def test_timed_enrollment_validity(self) -> None:
        validity = _period((2026, 11, 22, 19, 46), (2027, 11, 22, 19, 46))
        assert _sent("enroll by tap, timed")[1] == cmd.payload_card_modify(FIRST_CARD, validity)

    def test_modify_after_a_weekly_edit(self) -> None:
        validity = _period((2026, 11, 19, 1, 0), (2027, 11, 20, 0, 59))
        sent = _sent("change a recurring card's validity and weekly days")[0]
        assert sent == cmd.payload_card_modify(SECOND_CARD, validity)

    def test_delete_one(self) -> None:
        assert _sent("delete one card") == [cmd.payload_card_delete(FIRST_CARD)]

    def test_clear_all(self) -> None:
        assert _sent("clear all cards (app: reset)") == [cmd.payload_card_clear()]

    def test_a_weekly_validity_sends_its_dates_like_a_period(self) -> None:
        start, end = dt.datetime(2026, 11, 19, 1), dt.datetime(2027, 11, 20, 0, 59)  # noqa: DTZ001
        weekly = Weekly((_MONDAY,), start, end)
        assert cmd.payload_card_modify(SECOND_CARD, weekly) == cmd.payload_card_modify(
            SECOND_CARD, Period(start, end)
        )


class TestCapturedReplies:
    def test_the_lock_waiting_for_a_card(self) -> None:
        for operation in (
            "enroll by tap, permanent",
            "enroll by tap, no card presented",
            "enroll by tap, second card, permanent",
            "enroll by tap, timed",
        ):
            assert cmd.parse_card_enrollment_reply(_received(operation)[0]) is None

    @pytest.mark.parametrize(
        ("operation", "card"),
        [
            ("enroll by tap, permanent", FIRST_CARD),
            ("enroll by tap, second card, permanent", SECOND_CARD),
            ("enroll by tap, timed", FIRST_CARD),
        ],
    )
    def test_the_card_pushed_when_presented(self, operation: str, card: bytes) -> None:
        assert cmd.parse_card_enrollment_reply(_received(operation)[1]) == card

    def test_a_card_that_is_never_presented_pushes_nothing(self) -> None:
        assert len(_received("enroll by tap, no card presented")) == 1

    def test_acknowledgements(self) -> None:
        assert _received("enroll by tap, timed")[2] == bytes.fromhex("4005")
        assert _received("delete one card") == [bytes.fromhex("4303")]
        assert _received("clear all cards (app: reset)") == [bytes.fromhex("4404")]

    def test_an_eight_byte_id_is_accepted(self) -> None:
        pushed = bytes.fromhex("44 02 01") + bytes(range(1, 9))
        assert cmd.parse_card_enrollment_reply(pushed) == bytes(range(1, 9))

    @pytest.mark.parametrize(
        "data",
        [
            pytest.param(b"", id="empty"),
            pytest.param(bytes.fromhex("44 02"), id="no state"),
            pytest.param(bytes.fromhex("44 05 02"), id="other sub-op"),
            pytest.param(bytes.fromhex("44 02 03"), id="unknown state"),
            pytest.param(bytes.fromhex("44 02 02 00"), id="waiting with a tail"),
            pytest.param(bytes.fromhex("44 02 01"), id="card without an id"),
            pytest.param(bytes.fromhex("44 02 01 55 66 77"), id="three-byte id"),
        ],
    )
    def test_anything_else_is_refused_without_echoing_it(self, data: bytes) -> None:
        with pytest.raises(ValueError, match="unexpected reply") as raised:
            cmd.parse_card_enrollment_reply(data)
        if data:
            assert data.hex() not in str(raised.value)


class TestSdkOnlyPayloads:
    def test_add_by_number_layout(self) -> None:
        validity = _period((2026, 11, 22, 19, 46), (2027, 11, 22, 19, 46))
        assert cmd.payload_card_add(FIRST_CARD, validity) == (
            bytes.fromhex("02 55667788 1a0b16132e 1b0b16132e")
        )

    def test_add_permanent_uses_the_dates_the_lock_lists_for_permanent(self) -> None:
        assert cmd.payload_card_add(FIRST_CARD, Permanent()) == (
            bytes([0x02]) + FIRST_CARD + _PERMANENT_DATES
        )
        assert bytes.fromhex("00 01 01 00 00  63 01 01 00 00") == _PERMANENT_DATES

    def test_add_with_an_eight_byte_id(self) -> None:
        eight = Credential.card(0x1_0000_0000).identifier
        assert cmd.payload_card_add(eight, Permanent())[1:9] == eight

    def test_modify_permanent(self) -> None:
        assert cmd.payload_card_modify(FIRST_CARD, Permanent()) == (
            bytes([0x05]) + FIRST_CARD + _PERMANENT_DATES
        )

    def test_an_unbounded_weekly_validity_is_permanent_dates(self) -> None:
        assert cmd.payload_card_modify(FIRST_CARD, Weekly((_MONDAY,))) == (
            cmd.payload_card_modify(FIRST_CARD, Permanent())
        )

    @pytest.mark.parametrize(
        "build", [cmd.payload_card_add, cmd.payload_card_modify], ids=["add", "modify"]
    )
    def test_single_use_is_refused(self, build) -> None:
        single = SingleUse(dt.datetime(2026, 1, 1), dt.datetime(2026, 1, 2))  # noqa: DTZ001
        with pytest.raises(ValueError, match="single-use"):
            build(FIRST_CARD, single)
        with pytest.raises(ValueError, match="single-use"):
            cmd.check_card_validity(single)
