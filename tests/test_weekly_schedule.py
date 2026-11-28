"""Offline tests for the weekly-schedule codec (CMD 0x70) against captured bytes.

Fixtures in `tests/fixtures/weekly_schedule/` are sanitized captures from a
lock of model SN484_PV53; card ids are the placeholders 0x11223344 and
0x55667788.

UNCONVENTIONAL SAFEGUARD (keep through any style pass):
`test_forbidden_operations_are_unreachable` inspects the package for
defined operation values other than 1, 2 and 4 and for any public parameter
that could select an operation. Intent: operation 3 (REMOVE, layout unknown) and operation 5
(disconnected the lock in earlier probing) must never be sendable through
this API.
"""

from __future__ import annotations

import datetime as dt
import inspect
import json
import logging
from pathlib import Path

import pytest

from ttlock_ble.commands import weekly_schedule as ws
from ttlock_ble.commands.weekly_schedule import operations
from ttlock_ble.exceptions import TTLockError

FIXTURES = Path(__file__).parent / "fixtures" / "weekly_schedule"
FINGERPRINT = ws.CredentialType.FINGERPRINT
CARD = ws.CredentialType.CARD
CARD_ID = ws.card_credential_id(0x11223344)
FINGERPRINT_ID = ws.fingerprint_credential_id(bytes.fromhex("aabbcc03"), 9)
MONDAY_WINDOW = (dt.time(20, 14), dt.time(21, 14))


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _frames(edit: dict, direction: str) -> list[bytes]:
    """The CMD 0x70 plaintexts of one direction; RX frames are 0x54 responses echoing 0x70."""
    command = "0x70" if direction == "TX" else "0x54"
    return [
        bytes.fromhex(frame["plaintext"])
        for frame in edit["frames"]
        if frame["direction"] == direction
        and frame["command"] == command
        and frame["plaintext"].startswith("70" if direction == "RX" else "0")
    ]


def _windows_from_adds(adds: list[bytes], id_length: int) -> dict[int, tuple[dt.time, dt.time]]:
    windows = {}
    for add in adds:
        record = ws.decode_record(add[3 + id_length : 3 + id_length + 7])
        windows[record.weekday] = (record.start_time, record.end_time)
    return windows


EDIT_FIXTURES = [
    ("fixture_card_schedule_edits.json", CARD, CARD_ID),
    ("fixture_fingerprint_schedule_edits.json", FINGERPRINT, FINGERPRINT_ID),
]


@pytest.mark.parametrize(("name", "credential_type", "credential_id"), EDIT_FIXTURES)
def test_write_plan_reproduces_captured_frames(name, credential_type, credential_id) -> None:
    for edit in _load(name)["edits"]:
        captured = _frames(edit, "TX")
        windows = _windows_from_adds(captured[1:], len(credential_id))
        plan = ws.plan_weekly_schedule_write(credential_type, credential_id, windows)
        assert list(plan) == captured, edit["change"]
        assert plan[0] == ws.payload_weekly_schedule_clear(credential_type, credential_id)
        for add, payload in zip(captured[1:], plan[1:], strict=True):
            record = ws.decode_record(add[3 + len(credential_id) : 3 + len(credential_id) + 7])
            assert payload == ws.payload_weekly_schedule_add(credential_type, credential_id, record)


@pytest.mark.parametrize(("name", "credential_type", "credential_id"), EDIT_FIXTURES)
def test_captured_write_replies_parse(name, credential_type, credential_id) -> None:
    for edit in _load(name)["edits"]:
        sent = _frames(edit, "TX")
        replies = _frames(edit, "RX")
        assert len(sent) == len(replies)
        for request, reply in zip(sent, replies, strict=True):
            data = reply[2:]
            assert reply[:2] == bytes([0x70, 0x01])
            if request[0] == 0x04:
                assert ws.parse_weekly_schedule_clear_reply(data).operation == 0x04
            else:
                assert ws.parse_weekly_schedule_add_reply(data).operation == 0x02


QUERY_FIXTURES = [
    ("fixture_cyclic_query_fingerprint.json", FINGERPRINT, FINGERPRINT_ID, 6),
    ("fixture_cyclic_query_card.json", CARD, CARD_ID, 4),
]


@pytest.mark.parametrize(("name", "credential_type", "credential_id", "_"), QUERY_FIXTURES)
def test_query_payloads_equal_captured_requests(name, credential_type, credential_id, _) -> None:
    cursors = [None, 1, 2]
    for exchange, cursor in zip(_load(name)["exchanges"], cursors, strict=True):
        built = ws.payload_weekly_schedule_query(credential_type, credential_id, cursor)
        assert built == bytes.fromhex(exchange["request"])


@pytest.mark.parametrize(("name", "credential_type", "credential_id", "_"), QUERY_FIXTURES)
def test_query_replies_parse(name, credential_type, credential_id, _) -> None:
    replies = [
        ws.parse_weekly_schedule_query_reply(bytes.fromhex(exchange["reply_data"]))
        for exchange in _load(name)["exchanges"]
    ]
    assert [reply.position for reply in replies] == [1, 2, 1]
    assert [reply.record.weekday for reply in replies] == [1, 4, 1]
    assert all(reply.credential_type == credential_type for reply in replies)
    assert all(reply.credential_id == credential_id for reply in replies)
    assert all(reply.battery == 0x40 for reply in replies)
    assert replies[0].record.start_time < replies[0].record.end_time


async def test_read_schedule_from_fingerprint_fixture() -> None:
    exchanges = _load("fixture_cyclic_query_fingerprint.json")["exchanges"]
    records = await ws.read_weekly_schedule(_scripted(exchanges, FINGERPRINT, FINGERPRINT_ID))
    assert [(r.weekday, r.start_time, r.end_time) for r in records] == [
        (1, dt.time(21, 18), dt.time(23, 18)),
        (4, dt.time(21, 18), dt.time(23, 18)),
    ]


async def test_read_schedule_from_card_fixture() -> None:
    exchanges = _load("fixture_cyclic_query_card.json")["exchanges"]
    records = await ws.read_weekly_schedule(_scripted(exchanges, CARD, CARD_ID))
    assert [(r.weekday, r.start_time, r.end_time) for r in records] == [
        (1, dt.time(20, 14), dt.time(21, 14)),
        (4, dt.time(20, 14), dt.time(21, 14)),
    ]


def _scripted(exchanges: list[dict], credential_type, credential_id: bytes):
    """A query stub that checks each request against the capture and replays its reply."""
    expected = iter(exchanges)

    async def query(cursor: int | None) -> bytes | None:
        exchange = next(expected)
        built = ws.payload_weekly_schedule_query(credential_type, credential_id, cursor)
        assert built == bytes.fromhex(exchange["request"])
        return bytes.fromhex(exchange["reply_data"])

    return query


def _reply(position: int, weekday: int, credential_id: bytes = CARD_ID) -> bytes:
    record = ws.WeeklyScheduleRecord(weekday, dt.time(8, 0), dt.time(9, 30))
    return (
        bytes([0x40, 0x01])
        + position.to_bytes(2, "big")
        + bytes([CARD, len(credential_id)])
        + credential_id
        + ws.encode_record(record)
    )


class _Lock:
    """Stand-in for a lock holding a list of weekdays; replies like the captured walk."""

    def __init__(self, weekdays: list[int]) -> None:
        self.weekdays = weekdays
        self.cursors: list[int | None] = []

    async def query(self, cursor: int | None) -> bytes | None:
        self.cursors.append(cursor)
        if not self.weekdays:
            return None
        index = cursor if cursor is not None and cursor < len(self.weekdays) else 0
        return _reply(index + 1, self.weekdays[index])


async def test_read_full_week_stops_after_seven_records() -> None:
    lock = _Lock([7, 1, 2, 3, 4, 5, 6])
    records = await ws.read_weekly_schedule(lock.query)
    assert [record.weekday for record in records] == [7, 1, 2, 3, 4, 5, 6]
    assert lock.cursors == [None, 1, 2, 3, 4, 5, 6]


async def test_read_partial_week_stops_on_wrap() -> None:
    lock = _Lock([2, 5, 6])
    records = await ws.read_weekly_schedule(lock.query)
    assert [record.weekday for record in records] == [2, 5, 6]
    assert lock.cursors == [None, 1, 2, 3]


async def test_read_wrap_to_equal_position_stops() -> None:
    replies = iter([_reply(1, 3), _reply(1, 3)])

    async def query(cursor: int | None) -> bytes | None:
        return next(replies)

    assert len(await ws.read_weekly_schedule(query)) == 1


async def test_read_never_wrapping_lock_is_bounded_at_seven() -> None:
    calls = 0

    async def query(cursor: int | None) -> bytes | None:
        nonlocal calls
        calls += 1
        return _reply(calls, 1)

    assert len(await ws.read_weekly_schedule(query)) == ws.MAX_RECORDS
    assert calls == ws.MAX_RECORDS


async def test_read_no_reply_on_first_query_means_no_schedule() -> None:
    assert await ws.read_weekly_schedule(_Lock([]).query) == []


async def test_read_no_reply_mid_walk_is_an_error() -> None:
    replies = iter([_reply(1, 1), None])

    async def query(cursor: int | None) -> bytes | None:
        return next(replies)

    with pytest.raises(TTLockError, match="no reply"):
        await ws.read_weekly_schedule(query)


async def test_read_malformed_reply_is_an_error() -> None:
    async def query(cursor: int | None) -> bytes | None:
        return b"\x40\x01"

    with pytest.raises(TTLockError, match="too short"):
        await ws.read_weekly_schedule(query)


async def test_read_reply_for_different_credential_is_an_error() -> None:
    replies = iter([_reply(1, 1), _reply(2, 2, ws.card_credential_id(0x55667788))])

    async def query(cursor: int | None) -> bytes | None:
        return next(replies)

    with pytest.raises(TTLockError, match="different credential"):
        await ws.read_weekly_schedule(query)


def test_record_round_trip_every_weekday() -> None:
    for weekday in range(1, 8):
        record = ws.WeeklyScheduleRecord(weekday, dt.time(0, 0), dt.time(23, 59))
        assert ws.decode_record(ws.encode_record(record)) == record


def test_record_preserves_raw_kind_and_month() -> None:
    record = ws.decode_record(bytes([2, 3, 11, 1, 2, 3, 4]))
    assert (record.kind, record.month) == (2, 11)
    assert ws.encode_record(record) == bytes([2, 3, 11, 1, 2, 3, 4])
    assert ws.decode_record(bytes([1, 1, 0, 1, 2, 3, 4])).kind == ws.WEEKLY_KIND


@pytest.mark.parametrize("weekday", [0, 8, -1])
def test_record_rejects_invalid_weekday(weekday) -> None:
    with pytest.raises(ValueError, match="weekday"):
        ws.WeeklyScheduleRecord(weekday, dt.time(1, 0), dt.time(2, 0))


@pytest.mark.parametrize(
    "data",
    [
        bytes([1, 0, 0, 1, 0, 2, 0]),
        bytes([1, 8, 0, 1, 0, 2, 0]),
        bytes([1, 1, 0, 24, 0, 2, 0]),
        bytes([1, 1, 0, 1, 60, 2, 0]),
        bytes([1, 1, 0, 1, 0, 24, 0]),
        bytes([1, 1, 0, 1, 0, 2, 60]),
    ],
)
def test_decode_rejects_out_of_range(data) -> None:
    with pytest.raises(ValueError, match="invalid weekly schedule record"):
        ws.decode_record(data)


@pytest.mark.parametrize("length", [0, 6, 8])
def test_decode_rejects_wrong_length(length) -> None:
    with pytest.raises(ValueError, match="7 bytes"):
        ws.decode_record(bytes([1, 1, 0, 1, 0, 2, 0, 0])[:length] if length < 8 else bytes(8))


def test_record_rejects_seconds_timezone_and_oversized_bytes() -> None:
    with pytest.raises(ValueError, match="hour and minute only"):
        ws.WeeklyScheduleRecord(1, dt.time(1, 0, 5), dt.time(2, 0))
    with pytest.raises(ValueError, match="hour and minute only"):
        ws.WeeklyScheduleRecord(1, dt.time(1, 0), dt.time(2, 0, tzinfo=dt.UTC))
    with pytest.raises(ValueError, match="kind"):
        ws.WeeklyScheduleRecord(1, dt.time(1, 0), dt.time(2, 0), kind=256)
    with pytest.raises(ValueError, match="month"):
        ws.WeeklyScheduleRecord(1, dt.time(1, 0), dt.time(2, 0), month=-1)


def test_credential_id_helpers() -> None:
    assert bytes.fromhex("aabbcc030009") == FINGERPRINT_ID
    assert ws.card_credential_id(0x11223344) == bytes.fromhex("11223344")
    assert ws.card_credential_id(0) == bytes(4)
    assert ws.card_credential_id(0xFFFFFFFF) == b"\xff" * 4
    assert ws.card_credential_id(0x100000000) == bytes.fromhex("0000000100000000")
    assert ws.card_credential_id(0xFFFFFFFFFFFFFFFF) == b"\xff" * 8


@pytest.mark.parametrize("card_number", [-1, 0x10000000000000000])
def test_card_credential_id_rejects_out_of_range(card_number) -> None:
    with pytest.raises(ValueError, match="card_number"):
        ws.card_credential_id(card_number)


def test_fingerprint_credential_id_rejects_bad_input() -> None:
    with pytest.raises(ValueError, match="fingerprint_id"):
        ws.fingerprint_credential_id(b"\x01\x02\x03", 1)
    with pytest.raises(ValueError, match="slot"):
        ws.fingerprint_credential_id(bytes(4), 0x10000)
    with pytest.raises(ValueError, match="slot"):
        ws.fingerprint_credential_id(bytes(4), -1)


def test_payload_builders_validate_credentials() -> None:
    with pytest.raises(ValueError, match="credential_id"):
        ws.payload_weekly_schedule_clear(CARD, FINGERPRINT_ID)
    with pytest.raises(ValueError, match="credential_id"):
        ws.payload_weekly_schedule_query(FINGERPRINT, CARD_ID)
    with pytest.raises(ValueError, match="unknown credential_type"):
        ws.payload_weekly_schedule_clear(3, CARD_ID)
    with pytest.raises(ValueError, match="cursor"):
        ws.payload_weekly_schedule_query(CARD, CARD_ID, 0x10000)
    with pytest.raises(ValueError, match="cursor"):
        ws.payload_weekly_schedule_query(CARD, CARD_ID, -1)


def test_query_without_cursor_equals_cursor_zero() -> None:
    assert ws.payload_weekly_schedule_query(CARD, CARD_ID) == ws.payload_weekly_schedule_query(
        CARD, CARD_ID, 0
    )
    assert len(ws.payload_weekly_schedule_query(CARD, CARD_ID)) == 20


def test_eight_byte_card_payloads() -> None:
    long_id = ws.card_credential_id(0x100000000)
    assert ws.payload_weekly_schedule_clear(CARD, long_id) == bytes([4, 2, 8]) + long_id
    assert len(ws.payload_weekly_schedule_query(CARD, long_id, 3)) == 20


def test_query_reply_rejects_malformed_data() -> None:
    good = _reply(1, 1)
    with pytest.raises(ValueError, match="too short"):
        ws.parse_weekly_schedule_query_reply(good[:5])
    with pytest.raises(ValueError, match="too short"):
        ws.parse_weekly_schedule_query_reply(b"")
    with pytest.raises(ValueError, match="truncated or id_len overruns"):
        ws.parse_weekly_schedule_query_reply(good[:-1])
    overrunning = good[:5] + bytes([200]) + good[6:]
    with pytest.raises(ValueError, match="truncated or id_len overruns"):
        ws.parse_weekly_schedule_query_reply(overrunning)
    with pytest.raises(ValueError, match="echoes operation"):
        ws.parse_weekly_schedule_query_reply(good[:1] + b"\x02" + good[2:])
    bad_record = good[:-7] + bytes([1, 9, 0, 1, 0, 2, 0])
    with pytest.raises(ValueError, match="invalid weekly schedule record"):
        ws.parse_weekly_schedule_query_reply(bad_record)


def test_query_reply_with_empty_credential_id_is_still_length_checked() -> None:
    record = ws.encode_record(ws.WeeklyScheduleRecord(1, dt.time(1, 0), dt.time(2, 0)))
    data = bytes([0x40, 0x01, 0, 1, 2, 0]) + record
    assert ws.parse_weekly_schedule_query_reply(data).credential_id == b""


def test_write_replies_reject_mismatched_echo_and_length() -> None:
    assert ws.parse_weekly_schedule_clear_reply(bytes([0x40, 0x04])).battery == 0x40
    assert ws.parse_weekly_schedule_add_reply(bytes([0x11, 0x02])).battery == 0x11
    with pytest.raises(ValueError, match="echoes operation"):
        ws.parse_weekly_schedule_clear_reply(bytes([0x40, 0x02]))
    with pytest.raises(ValueError, match="echoes operation"):
        ws.parse_weekly_schedule_add_reply(bytes([0x40, 0x04]))
    for data in (b"", b"\x40"):
        with pytest.raises(ValueError, match="too short"):
            ws.parse_weekly_schedule_add_reply(data)


def test_query_reply_ignores_trailing_bytes(caplog) -> None:
    good = _reply(2, 3)
    with caplog.at_level(logging.DEBUG, logger="ttlock_ble.weekly_schedule"):
        reply = ws.parse_weekly_schedule_query_reply(good + b"\xaa\xbb")
    assert reply == ws.parse_weekly_schedule_query_reply(good)
    assert "Ignoring 2 trailing bytes" in caplog.text
    assert "aabb" not in caplog.text


def test_write_replies_ignore_trailing_bytes(caplog) -> None:
    with caplog.at_level(logging.DEBUG, logger="ttlock_ble.weekly_schedule"):
        clear = ws.parse_weekly_schedule_clear_reply(bytes([0x40, 0x04, 0x00, 0x01]))
        add = ws.parse_weekly_schedule_add_reply(bytes([0x40, 0x02, 0x09]))
    assert (clear.battery, clear.operation) == (0x40, 0x04)
    assert (add.battery, add.operation) == (0x40, 0x02)
    assert caplog.text.count("Ignoring") == 2
    with pytest.raises(ValueError, match="echoes operation"):
        ws.parse_weekly_schedule_clear_reply(bytes([0x40, 0x02, 0x00]))


def test_write_plan_sorts_weekdays_and_rejects_bad_input() -> None:
    plan = ws.plan_weekly_schedule_write(
        CARD, CARD_ID, {5: MONDAY_WINDOW, 2: MONDAY_WINDOW, 6: MONDAY_WINDOW}
    )
    assert [payload[0] for payload in plan] == [4, 2, 2, 2]
    assert [payload[8] for payload in plan[1:]] == [2, 5, 6]
    with pytest.raises(ValueError, match="must not be empty"):
        ws.plan_weekly_schedule_write(CARD, CARD_ID, {})
    with pytest.raises(ValueError, match="weekday"):
        ws.plan_weekly_schedule_write(CARD, CARD_ID, {8: MONDAY_WINDOW})


def test_forbidden_operations_are_unreachable() -> None:
    allowed = {0x01, 0x02, 0x04}
    constants = {
        name: value
        for name, value in vars(operations).items()
        if name.endswith("_OPERATION") and isinstance(value, int)
    }
    assert set(constants.values()) == allowed

    built = {
        ws.payload_weekly_schedule_query(CARD, CARD_ID)[0],
        ws.payload_weekly_schedule_clear(CARD, CARD_ID)[0],
        ws.payload_weekly_schedule_add(
            CARD, CARD_ID, ws.WeeklyScheduleRecord(1, dt.time(1, 0), dt.time(2, 0))
        )[0],
    }
    assert built == allowed

    for name in ws.__all__:
        member = getattr(ws, name)
        if callable(member) and not inspect.isclass(member):
            parameters = set(inspect.signature(member).parameters)
            assert not parameters & {"op", "operation", "opcode", "sub_op"}, name


async def test_read_accepts_matching_expected_credential() -> None:
    lock = _Lock([2, 5])
    records = await ws.read_weekly_schedule(lock.query, expected_credential=(CARD, CARD_ID))
    assert [record.weekday for record in records] == [2, 5]


async def test_read_rejects_reply_for_other_credential_than_expected() -> None:
    other = ws.card_credential_id(0x55667788)

    async def query(cursor: int | None) -> bytes | None:
        return _reply(1, 1, other)

    with pytest.raises(TTLockError, match="different credential"):
        await ws.read_weekly_schedule(query, expected_credential=(CARD, CARD_ID))


async def test_read_rejects_reply_of_other_credential_type_than_expected() -> None:
    async def query(cursor: int | None) -> bytes | None:
        return _reply(1, 1)

    with pytest.raises(TTLockError, match="different credential"):
        await ws.read_weekly_schedule(query, expected_credential=(FINGERPRINT, CARD_ID))
