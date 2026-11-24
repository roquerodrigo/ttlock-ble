"""Validity value objects reject what a lock cannot store."""

from __future__ import annotations

import datetime as dt

import pytest

from ttlock_ble import Period, Permanent, SingleUse, Validity, Weekday, Weekly, WeeklyWindow
from ttlock_ble.commands.encoding import decode_date5, encode_date5

_START = dt.datetime(2026, 11, 23, 14, 0)  # noqa: DTZ001 -- lock-local wall clock
_END = dt.datetime(2026, 11, 30, 18, 30)  # noqa: DTZ001 -- lock-local wall clock
_MORNING = WeeklyWindow(Weekday.MONDAY, dt.time(8, 0), dt.time(12, 0))


def test_permanent_is_a_value() -> None:
    assert Permanent() == Permanent()


@pytest.mark.parametrize("kind", [Period, SingleUse])
def test_dated_validity_keeps_its_range(kind: type[Period | SingleUse]) -> None:
    validity = kind(_START, _END)
    assert (validity.start, validity.end) == (_START, _END)


@pytest.mark.parametrize("kind", [Period, SingleUse])
def test_dated_validity_must_start_before_it_ends(kind: type[Period | SingleUse]) -> None:
    with pytest.raises(ValueError, match="start before it ends"):
        kind(_END, _START)


def test_range_shorter_than_a_minute_is_rejected() -> None:
    with pytest.raises(ValueError, match="to the minute"):
        Period(_START, _START.replace(second=59))


@pytest.mark.parametrize("year", [1999, 2100])
def test_range_outside_the_lock_calendar_is_rejected(year: int) -> None:
    with pytest.raises(ValueError, match="between 2000 and 2099"):
        Period(_START.replace(year=year), _END.replace(year=2026 if year < 2000 else year))


def test_aware_and_naive_bounds_compare_by_wall_clock() -> None:
    aware_end = _END.replace(tzinfo=dt.timezone(dt.timedelta(hours=-3)))
    assert Period(_START, aware_end).end is aware_end


def test_weekly_validity_keeps_windows_as_a_tuple() -> None:
    evening = WeeklyWindow(Weekday.FRIDAY, dt.time(18, 0), dt.time(23, 59))
    validity = Weekly([_MORNING, evening], _START, _END)  # type: ignore[arg-type]
    assert validity.windows == (_MORNING, evening)
    assert validity.is_bounded
    assert hash(validity)


def test_weekly_validity_may_repeat_indefinitely() -> None:
    validity = Weekly((_MORNING,))
    assert (validity.start, validity.end) == (None, None)
    assert not validity.is_bounded


def test_weekly_validity_needs_both_bounds_or_neither() -> None:
    with pytest.raises(ValueError, match="both a start and an end, or neither"):
        Weekly((_MORNING,), _START)


def test_weekly_validity_needs_a_window() -> None:
    with pytest.raises(ValueError, match="at least one window"):
        Weekly((), _START, _END)


def test_weekly_validity_allows_one_window_per_weekday() -> None:
    afternoon = WeeklyWindow(Weekday.MONDAY, dt.time(13, 0), dt.time(17, 0))
    with pytest.raises(ValueError, match="one window per weekday"):
        Weekly((_MORNING, afternoon), _START, _END)


def test_weekly_validity_checks_its_date_range() -> None:
    with pytest.raises(ValueError, match="weekly validity must start before it ends"):
        Weekly((_MORNING,), _END, _START)


def test_window_must_start_before_it_ends() -> None:
    with pytest.raises(ValueError, match="same day"):
        WeeklyWindow(Weekday.MONDAY, dt.time(22, 0), dt.time(2, 0))


def test_window_ignores_seconds() -> None:
    with pytest.raises(ValueError, match="same day"):
        WeeklyWindow(Weekday.MONDAY, dt.time(8, 0, 1), dt.time(8, 0, 59))


def test_window_rejects_an_unknown_weekday() -> None:
    with pytest.raises(ValueError, match="is not a valid Weekday"):
        WeeklyWindow(8, dt.time(8, 0), dt.time(9, 0))  # type: ignore[arg-type]


def test_weekday_matches_isoweekday() -> None:
    assert Weekday(_START.isoweekday()) is Weekday.MONDAY
    assert Weekday.SUNDAY == 7


def test_validity_alias_covers_every_kind() -> None:
    assert set(Validity.__value__.__args__) == {Permanent, Period, SingleUse, Weekly}


def test_encode_date5_round_trips_through_decode() -> None:
    raw = encode_date5(_START.replace(second=42))
    assert raw == bytes([26, 11, 23, 14, 0])
    assert decode_date5(raw) == _START


def test_encode_date5_rejects_years_a_byte_cannot_hold() -> None:
    with pytest.raises(ValueError, match="2000-2099"):
        encode_date5(_START.replace(year=2100))


def test_window_stores_a_weekday_given_as_int() -> None:
    window = WeeklyWindow(2, dt.time(8, 0), dt.time(9, 0))  # type: ignore[arg-type]
    assert window.weekday is Weekday.TUESDAY
