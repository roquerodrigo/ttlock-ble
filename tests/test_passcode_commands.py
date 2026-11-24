"""Byte layouts of the passcode write commands and the weekly cycle type."""

from __future__ import annotations

import datetime as dt

import pytest

from ttlock_ble import Period, Permanent, SingleUse, Weekday, Weekly, WeeklyWindow
from ttlock_ble import commands as cmd

_CODE = "38150627"
_NEW_CODE = "51207349"
_START = dt.datetime(2026, 11, 23, 21, 33)  # noqa: DTZ001 -- lock-local wall clock
_END = dt.datetime(2026, 11, 25, 21, 33)  # noqa: DTZ001 -- lock-local wall clock
_START_BYTES = bytes([26, 11, 23, 21, 33])
_END_BYTES = bytes([26, 11, 25, 21, 33])


def _prefixed(code: str) -> bytes:
    return bytes([len(code)]) + code.encode()


def _weekly(days: tuple[Weekday, ...], opens: dt.time, closes: dt.time) -> Weekly:
    return Weekly(tuple(WeeklyWindow(day, opens, closes) for day in days))


_WORKDAYS = (Weekday.MONDAY, Weekday.TUESDAY, Weekday.WEDNESDAY, Weekday.THURSDAY, Weekday.FRIDAY)
_WEEKEND = (Weekday.SATURDAY, Weekday.SUNDAY)


class TestCreate:
    def test_permanent_carries_only_the_unset_start(self) -> None:
        assert cmd.payload_passcode_create(_CODE, Permanent()) == (
            bytes([0x02, 0x01]) + _prefixed(_CODE) + bytes([0, 1, 1, 0, 0])
        )

    def test_period_carries_both_dates(self) -> None:
        assert cmd.payload_passcode_create(_CODE, Period(_START, _END)) == (
            bytes([0x02, 0x03]) + _prefixed(_CODE) + _START_BYTES + _END_BYTES
        )

    def test_single_use_is_a_count_passcode(self) -> None:
        assert cmd.payload_passcode_create(_CODE, SingleUse(_START, _END)) == (
            bytes([0x02, 0x02]) + _prefixed(_CODE) + _START_BYTES + _END_BYTES
        )

    @pytest.mark.parametrize("code", ["123", "1234567890", "12a4", "١٢٣٤"])
    def test_invalid_code_is_rejected_without_quoting_it(self, code: str) -> None:
        with pytest.raises(ValueError, match="4-9 digits") as error:
            cmd.payload_passcode_create(code, Permanent())
        assert code not in str(error.value)


class TestRecoverWeekly:
    def test_layout_matches_what_the_lock_accepted(self) -> None:
        weekly = _weekly((Weekday.MONDAY,), dt.time(17), dt.time(19))
        assert cmd.payload_passcode_recover_weekly(_CODE, weekly) == (
            bytes([0x06, 0x04])
            + _prefixed(_CODE)
            + _prefixed(_CODE)
            + bytes([0, 1, 1, 17, 0])
            + bytes([0x04, 0x31])
        )

    def test_keeps_the_start_minute(self) -> None:
        weekly = _weekly((Weekday.MONDAY,), dt.time(17, 30), dt.time(19, 30))
        assert cmd.payload_passcode_recover_weekly(_CODE, weekly)[-4:] == bytes(
            [17, 30, 0x04, 0x31]
        )


class TestPasscodeCycle:
    # Every row is a CIRCLE entry the lock itself reported (see
    # `test_cyclic_entry_real_captures`): encoding its schedule must give back
    # the trailer's start hour and last two bytes.
    @pytest.mark.parametrize(
        ("days", "opens", "hours", "cycle_type"),
        [
            ((Weekday.SUNDAY,), 17, 1, 0x04C0),
            (tuple(Weekday), 17, 1, 0x0400),
            (_WEEKEND, 17, 1, 0x03E8),
            ((Weekday.SATURDAY,), 17, 1, 0x04A8),
            ((Weekday.MONDAY,), 17, 1, 0x0430),
            (_WORKDAYS, 16, 2, 0x0419),
            ((Weekday.TUESDAY,), 17, 2, 0x0449),
            (_WEEKEND, 10, 10, 0x03F1),
        ],
    )
    def test_matches_the_lock_reported_schedules(
        self, days: tuple[Weekday, ...], opens: int, hours: int, cycle_type: int
    ) -> None:
        weekly = _weekly(days, dt.time(opens), dt.time(opens + hours))
        assert cmd.encode_passcode_cycle(weekly) == (dt.time(opens), cycle_type)

    def test_round_trips_through_the_list_decoder(self) -> None:
        weekly = _weekly((Weekday.THURSDAY,), dt.time(8), dt.time(13))
        start, cycle_type = cmd.encode_passcode_cycle(weekly)
        item = bytes([0x01, 0x04, 4]) + b"1234" + bytes([4]) + b"1234"
        trailer = bytes([0, 1, 1, start.hour, start.minute]) + cycle_type.to_bytes(2, "big")
        body = item[1:] + trailer
        plain = bytes([cmd.CMD_GET_PASSCODES, cmd.RESPONSE_SUCCESS, 0, 0, 0, 0, len(body)]) + body
        entry, _ = cmd.parse_passcode_list_response(plain)
        assert entry is not None
        assert entry.cyclic_schedule is not None
        assert entry.cyclic_schedule.day_or_preset == "Thursday"
        assert (entry.cyclic_schedule.start_hour, entry.cyclic_schedule.duration_hours) == (8, 5)

    @pytest.mark.parametrize(
        ("weekly", "message"),
        [
            (
                Weekly((WeeklyWindow(Weekday.MONDAY, dt.time(8), dt.time(9)),), _START, _END),
                "date range",
            ),
            (
                Weekly(
                    (
                        WeeklyWindow(Weekday.SATURDAY, dt.time(8), dt.time(9)),
                        WeeklyWindow(Weekday.SUNDAY, dt.time(9), dt.time(10)),
                    )
                ),
                "same hours",
            ),
            (_weekly((Weekday.MONDAY,), dt.time(8), dt.time(9, 30)), "whole hours"),
            (_weekly((Weekday.MONDAY, Weekday.WEDNESDAY), dt.time(8), dt.time(9)), "one weekday"),
        ],
    )
    def test_rejects_what_the_cycle_type_cannot_express(self, weekly: Weekly, message: str) -> None:
        with pytest.raises(ValueError, match=message):
            cmd.encode_passcode_cycle(weekly)


class TestModify:
    def test_new_code_only(self) -> None:
        assert cmd.payload_passcode_modify(_CODE, new_code=_NEW_CODE) == (
            bytes([0x05, 0x00]) + _prefixed(_CODE) + _prefixed(_NEW_CODE)
        )

    def test_dates_only(self) -> None:
        assert cmd.payload_passcode_modify(_CODE, validity=Period(_START, _END)) == (
            bytes([0x05, 0x00]) + _prefixed(_CODE) + bytes([0]) + _START_BYTES + _END_BYTES
        )

    def test_code_and_dates(self) -> None:
        payload = cmd.payload_passcode_modify(
            _CODE, new_code=_NEW_CODE, validity=SingleUse(_START, _END)
        )
        assert payload == (
            bytes([0x05, 0x00])
            + _prefixed(_CODE)
            + _prefixed(_NEW_CODE)
            + _START_BYTES
            + _END_BYTES
        )

    def test_needs_a_change(self) -> None:
        with pytest.raises(ValueError, match="new code, a new validity"):
            cmd.payload_passcode_modify(_CODE)

    def test_checks_the_new_code(self) -> None:
        with pytest.raises(ValueError, match="4-9 digits"):
            cmd.payload_passcode_modify(_CODE, new_code="12")


class TestAdminPasscode:
    def test_set_sends_digit_values(self) -> None:
        assert cmd.payload_set_admin_passcode("907135") == bytes([9, 0, 7, 1, 3, 5])

    def test_set_checks_the_code(self) -> None:
        with pytest.raises(ValueError, match="4-9 digits"):
            cmd.payload_set_admin_passcode("12")

    def test_parse_reads_ascii_digits(self) -> None:
        assert cmd.parse_admin_passcode(bytes([0x3A, 6]) + b"907135") == "907135"

    @pytest.mark.parametrize(
        "data",
        [b"", bytes([0x3A]), bytes([0x3A, 7]) + b"907135", bytes([0x3A, 6]) + b"90713x"],
    )
    def test_parse_rejects_without_quoting(self, data: bytes) -> None:
        with pytest.raises(ValueError) as error:
            cmd.parse_admin_passcode(data)
        assert "90713" not in str(error.value)
