"""Pure payload builders and response parsers in `commands.py` (byte-level)."""

from __future__ import annotations

import datetime as dt
from typing import TYPE_CHECKING

import pytest

from ttlock_ble import commands as cmd
from ttlock_ble.commands import log_record
from ttlock_ble.constants import KeyboardPwdType, LockState, LockVolume

if TYPE_CHECKING:
    from ttlock_ble.models import LogEntry


class TestPayloadBuilders:
    def test_check_random(self) -> None:
        assert cmd.payload_check_random(0x10, 0x20) == (0x30).to_bytes(4, "big")

    def test_check_user_time_is_17_bytes(self) -> None:
        out = cmd.payload_check_user_time(uid=5, lock_flag_pos=0x010203)
        assert len(out) == 17

    def test_check_admin_layout(self) -> None:
        out = cmd.payload_check_admin(uid=7, admin_ps="123456", lock_flag_pos=0x0A0B0C)
        assert len(out) == 11
        assert int.from_bytes(out[0:4], "big") == 123456
        assert int.from_bytes(out[7:11], "big") == 7

    def test_set_lock_sound_on(self) -> None:
        assert cmd.payload_set_lock_sound(enabled=True) == bytes([0x02, 0x01])

    def test_set_lock_sound_off(self) -> None:
        assert cmd.payload_set_lock_sound(enabled=False) == bytes([0x02, 0x00])

    def test_set_lock_volume_layout(self) -> None:
        assert cmd.payload_set_lock_volume(3) == bytes([0x02, 0x01, 3, 0x00])

    def test_set_lock_volume_boundaries_accepted(self) -> None:
        # LockVolume is an IntEnum, so a named member works anywhere a
        # plain int does - no separate code path, no signature change.
        assert cmd.payload_set_lock_volume(LockVolume.LOW) == bytes([0x02, 0x01, 1, 0x00])
        assert cmd.payload_set_lock_volume(LockVolume.HIGH) == bytes([0x02, 0x01, 5, 0x00])

    def test_set_lock_volume_rejects_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="1-5"):
            cmd.payload_set_lock_volume(min(LockVolume) - 1)
        with pytest.raises(ValueError, match="1-5"):
            cmd.payload_set_lock_volume(max(LockVolume) + 1)

    def test_unlock_uses_explicit_timestamp(self) -> None:
        out = cmd.payload_unlock(0x10, "20", ts_ms=2000)
        assert int.from_bytes(out[0:4], "big") == 0x10 + 20
        assert int.from_bytes(out[4:8], "big") == 2  # 2000ms → 2s

    def test_unlock_defaults_to_now(self) -> None:
        out = cmd.payload_unlock(1, "2")
        assert int.from_bytes(out[4:8], "big") > 0

    def test_get_aes_key_and_query_state(self) -> None:
        assert cmd.payload_get_aes_key()
        assert cmd.payload_query_state() == b"SCIENER"

    def test_time_calibrate_decimal_encoding(self) -> None:
        when = dt.datetime(2026, 5, 11, 14, 23, 7)  # noqa: DTZ001
        out = cmd.payload_time_calibrate(when)
        assert out == bytes([26, 5, 11, 14, 23, 7])

    def test_get_lock_time_empty(self) -> None:
        assert cmd.payload_get_lock_time() == b""

    def test_auto_lock_set_range_check(self) -> None:
        assert cmd.payload_auto_lock_set(0)[0:1]  # disable path
        with pytest.raises(ValueError, match="out of range"):
            cmd.payload_auto_lock_set(70000)

    def test_passcode_add_permanent_omits_end_window(self) -> None:
        out = cmd.payload_passcode_add(int(KeyboardPwdType.PERMANENT), "1234")
        # op + type + len + 4 code chars + 5 start = 12 bytes (no end window).
        assert len(out) == 12

    def test_passcode_add_period_includes_end_window(self) -> None:
        out = cmd.payload_passcode_add(int(KeyboardPwdType.PERIOD), "1234")
        assert len(out) == 17

    def test_passcode_validation_rejects_short(self) -> None:
        with pytest.raises(ValueError, match="4-9 digits"):
            cmd.payload_passcode_add(int(KeyboardPwdType.PERMANENT), "12")

    def test_passcode_delete_and_clear(self) -> None:
        assert cmd.payload_passcode_delete(int(KeyboardPwdType.PERMANENT), "1234")
        assert len(cmd.payload_passcode_clear()) == 1

    def test_operate_log_request(self) -> None:
        assert cmd.payload_operate_log_request() == b"\xff\xff"
        assert cmd.payload_operate_log_request(5) == b"\x00\x05"


class TestParsers:
    def test_response_status_too_short(self) -> None:
        with pytest.raises(ValueError, match="too short"):
            cmd.parse_response_status(b"\x01")

    def test_check_user_time_failure_raises(self) -> None:
        with pytest.raises(RuntimeError, match="FAILED"):
            cmd.parse_check_user_time_response(bytes([0x55, cmd.RESPONSE_FAILED, 0xFF]))

    def test_check_user_time_short_payload_raises(self) -> None:
        with pytest.raises(ValueError, match="too short"):
            cmd.parse_check_user_time_response(bytes([0x55, cmd.RESPONSE_SUCCESS, 0x01]))

    def test_check_admin_returns_token(self) -> None:
        plain = bytes([0x41, cmd.RESPONSE_SUCCESS]) + (0x87654321).to_bytes(4, "big")
        assert cmd.parse_check_admin_response(plain) == 0x87654321

    def test_check_admin_failure_raises(self) -> None:
        with pytest.raises(RuntimeError, match="FAILED"):
            cmd.parse_check_admin_response(bytes([0x41, cmd.RESPONSE_FAILED, 0xFF]))

    def test_check_admin_short_payload_raises(self) -> None:
        with pytest.raises(ValueError, match="too short"):
            cmd.parse_check_admin_response(bytes([0x41, cmd.RESPONSE_SUCCESS, 0x01]))

    def test_lock_status_failure_returns_none(self) -> None:
        assert cmd.parse_lock_status(bytes([0x14, cmd.RESPONSE_FAILED])) is None

    def test_lock_status_locked(self) -> None:
        plain = bytes([0x14, cmd.RESPONSE_SUCCESS, 0x2C, int(LockState.LOCKED)])
        assert cmd.parse_lock_status(plain) is LockState.LOCKED

    def test_lock_status_unknown_byte(self) -> None:
        plain = bytes([0x14, cmd.RESPONSE_SUCCESS, 0x2C, 0x09])
        assert cmd.parse_lock_status(plain) is None

    def test_state_battery_none_on_failure(self) -> None:
        assert cmd.parse_state_battery(bytes([0x14, cmd.RESPONSE_FAILED])) is None

    def test_state_battery_value(self) -> None:
        assert cmd.parse_state_battery(bytes([0x14, cmd.RESPONSE_SUCCESS, 0x55])) == 0x55

    def test_auto_lock_failure_raises(self) -> None:
        with pytest.raises(RuntimeError, match="FAILED"):
            cmd.parse_auto_lock_response(bytes([0x36, cmd.RESPONSE_FAILED]))

    def test_auto_lock_short_payload_raises(self) -> None:
        with pytest.raises(ValueError, match="too short"):
            cmd.parse_auto_lock_response(bytes([0x36, cmd.RESPONSE_SUCCESS, 0x01]))

    def test_auto_lock_modify_ack_has_no_seconds(self) -> None:
        plain = bytes([0x36, cmd.RESPONSE_SUCCESS, 90, 2])
        assert cmd.parse_auto_lock_response(plain) == (-1, 90)

    def test_auto_lock_search_truncated_raises(self) -> None:
        # op_type=1 (SEARCH) but the seconds bytes never arrived - this must
        # NOT collapse into the -1 sentinel a genuine MODIFY ack returns.
        with pytest.raises(ValueError, match="missing seconds"):
            cmd.parse_auto_lock_response(bytes([0x36, cmd.RESPONSE_SUCCESS, 90, 1]))

    def test_auto_lock_limits_returns_min_max(self) -> None:
        plain = (
            bytes([0x36, cmd.RESPONSE_SUCCESS, 90, 1])
            + (45).to_bytes(2, "big")
            + (1).to_bytes(2, "big")
            + (900).to_bytes(2, "big")
            + bytes([0x01])
        )
        limits = cmd.parse_auto_lock_limits_response(plain)
        assert limits.min_allowed == 1
        assert limits.max_allowed == 900

    def test_auto_lock_limits_short_payload_raises(self) -> None:
        with pytest.raises(ValueError, match="too short"):
            cmd.parse_auto_lock_limits_response(bytes([0x36, cmd.RESPONSE_SUCCESS, 0x01]))

    def test_auto_lock_limits_failure_raises(self) -> None:
        with pytest.raises(RuntimeError, match="FAILED"):
            cmd.parse_auto_lock_limits_response(bytes([0x36, cmd.RESPONSE_FAILED]))

    def test_auto_lock_limits_modify_ack_raises(self) -> None:
        # A MODIFY ack has no min/max fields at all - limits only exist on a
        # SEARCH response, unlike parse_auto_lock_response's -1 tolerance.
        plain = bytes([0x36, cmd.RESPONSE_SUCCESS, 90, 2])
        with pytest.raises(ValueError, match="SEARCH response"):
            cmd.parse_auto_lock_limits_response(plain)

    def test_auto_lock_limits_truncated_raises(self) -> None:
        plain = bytes([0x36, cmd.RESPONSE_SUCCESS, 90, 1]) + (45).to_bytes(2, "big")
        with pytest.raises(ValueError, match="missing min/max"):
            cmd.parse_auto_lock_limits_response(plain)

    def test_operate_log_failure_empty(self) -> None:
        assert cmd.parse_operate_log_response(bytes([0x25, cmd.RESPONSE_FAILED])) == ([], 0)

    def test_operate_log_empty_page(self) -> None:
        plain = bytes([0x25, cmd.RESPONSE_SUCCESS, 0x00, 0x00])
        assert cmd.parse_operate_log_response(plain) == ([], 0)

    def test_operate_log_truncated_record_breaks(self) -> None:
        # total_len > 0, sequence present, but a record claims more bytes than remain.
        body = bytes([0x05, 0x99])  # rec_len=5 but only 1 byte follows
        plain = (
            bytes([0x25, cmd.RESPONSE_SUCCESS])
            + (len(body) + 2).to_bytes(2, "big")
            + (1).to_bytes(2, "big")
            + body
        )
        entries, seq = cmd.parse_operate_log_response(plain)
        assert entries == []
        assert seq == 1


def _log_frame_plain(records: list[bytes], sequence: int) -> bytes:
    payload = bytearray()
    for r in records:
        payload.append(len(r))
        payload.extend(r)
    return (
        bytes([0x25, cmd.RESPONSE_SUCCESS])
        + (len(payload) + 5).to_bytes(2, "big")
        + sequence.to_bytes(2, "big")
        + bytes(payload)
    )


class TestLogRecordVariants:
    def _record(self, rtype: int, tail: bytes) -> bytes:
        return bytes([rtype]) + bytes([26, 5, 11, 14, 23, 7]) + bytes([90]) + tail

    def test_app_uid_record(self) -> None:
        tail = (123).to_bytes(4, "big") + (456).to_bytes(4, "big")
        plain = _log_frame_plain([self._record(1, tail)], sequence=3)
        entries, _ = cmd.parse_operate_log_response(plain)
        assert entries[0].uid == 123
        assert entries[0].record_id == 456

    def test_remote_control_key_record(self) -> None:
        tail = (1).to_bytes(4, "big") + (2).to_bytes(4, "big") + bytes([9])
        plain = _log_frame_plain([self._record(37, tail)], sequence=3)
        entries, _ = cmd.parse_operate_log_response(plain)
        assert entries[0].key_id == 9

    def test_card_long_record(self) -> None:
        tail = (0xABCDEF).to_bytes(4, "big")
        plain = _log_frame_plain([self._record(15, tail)], sequence=3)
        entries, _ = cmd.parse_operate_log_response(plain)
        assert entries[0].password == str(0xABCDEF)

    def test_fingerprint_record(self) -> None:
        tail = (0x010203040506).to_bytes(6, "big")
        plain = _log_frame_plain([self._record(20, tail)], sequence=3)
        entries, _ = cmd.parse_operate_log_response(plain)
        assert entries[0].password == str(0x010203040506)

    def test_door_sensor_record(self) -> None:
        plain = _log_frame_plain([self._record(30, bytes([77]))], sequence=3)
        entries, _ = cmd.parse_operate_log_response(plain)
        assert entries[0].accessory_battery == 77

    def test_bong_unlock_mac_record(self) -> None:
        mac = bytes([0x33, 0x22, 0x11, 0xCC, 0xBB, 0xAA])
        plain = _log_frame_plain([self._record(19, mac)], sequence=3)
        entries, _ = cmd.parse_operate_log_response(plain)
        assert entries[0].password == "aa:bb:cc:11:22:33"

    def test_wireless_fob_record(self) -> None:
        mac = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        tail = mac + bytes([3, 88])  # key_id + accessory battery
        plain = _log_frame_plain([self._record(55, tail)], sequence=3)
        entries, _ = cmd.parse_operate_log_response(plain)
        assert entries[0].key_id == 3
        assert entries[0].accessory_battery == 88

    def test_wireless_keypad_record(self) -> None:
        mac = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        plain = _log_frame_plain([self._record(56, mac + bytes([42]))], sequence=3)
        entries, _ = cmd.parse_operate_log_response(plain)
        assert entries[0].accessory_battery == 42

    def test_short_id_record(self) -> None:
        plain = _log_frame_plain([self._record(57, bytes([0x12, 0x34]))], sequence=3)
        entries, _ = cmd.parse_operate_log_response(plain)
        assert entries[0].password == str(0x1234)

    def test_six_byte_id_record(self) -> None:
        tail = (0x0A0B0C0D0E0F).to_bytes(6, "big")
        plain = _log_frame_plain([self._record(67, tail)], sequence=3)
        entries, _ = cmd.parse_operate_log_response(plain)
        assert entries[0].password == str(0x0A0B0C0D0E0F)

    def test_clear_all_record(self) -> None:
        tail = bytes([26, 5, 11, 14, 23])  # 5-byte delete date
        plain = _log_frame_plain([self._record(8, tail)], sequence=3)
        entries, _ = cmd.parse_operate_log_response(plain)
        assert entries[0].delete_date is not None

    def test_add_passcode_record(self) -> None:
        code = b"1234"
        start = bytes([26, 5, 11, 14, 23])
        end = bytes([26, 6, 11, 14, 23])
        tail = bytes([len(code)]) + code + start + end
        plain = _log_frame_plain([self._record(93, tail)], sequence=3)
        entries, _ = cmd.parse_operate_log_response(plain)
        assert entries[0].password == "1234"
        assert entries[0].start_date is not None
        assert entries[0].end_date is not None

    def test_third_device_mac_record(self) -> None:
        mac = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        plain = _log_frame_plain([self._record(94, mac)], sequence=3)
        entries, _ = cmd.parse_operate_log_response(plain)
        assert entries[0].password == "06:05:04:03:02:01"

    def test_error_pwd_only_record(self) -> None:
        tail = bytes([4]) + b"9999"
        plain = _log_frame_plain([self._record(7, tail)], sequence=3)
        entries, _ = cmd.parse_operate_log_response(plain)
        assert entries[0].password == "9999"

    def test_pwd_pair_with_new_password(self) -> None:
        tail = bytes([4]) + b"1111" + bytes([4]) + b"2222"
        plain = _log_frame_plain([self._record(4, tail)], sequence=3)
        entries, _ = cmd.parse_operate_log_response(plain)
        assert entries[0].password == "1111"
        assert entries[0].new_password == "2222"


class TestLogRecordTruncatedTails:
    """A body shorter than its record type's tail yields the header fields only."""

    def _entry(self, rtype: int, tail: bytes) -> LogEntry:
        plain = _log_frame_plain([bytes([rtype, 26, 5, 11, 14, 23, 7, 90]) + tail], sequence=3)
        entries, _ = cmd.parse_operate_log_response(plain)
        return entries[0]

    @pytest.mark.parametrize(
        ("record_type", "tail"),
        [
            (1, (7).to_bytes(4, "big")),
            (37, (1).to_bytes(4, "big") + (2).to_bytes(4, "big")),
            (8, bytes([26, 5, 11, 14])),
            (15, b""),
            (20, bytes([1, 2, 3])),
            (30, b""),
            (19, bytes([1, 2, 3])),
            (55, bytes([1, 2, 3])),
            (56, bytes([1, 2, 3])),
            (57, bytes([1])),
            (67, bytes([1, 2, 3])),
            (93, b""),
            (93, bytes([9]) + b"12"),
            (94, bytes([1, 2, 3])),
            (4, b""),
            (4, bytes([9]) + b"12"),
        ],
    )
    def test_short_tail_leaves_optional_fields_unset(self, record_type: int, tail: bytes) -> None:
        entry = self._entry(record_type, tail)
        assert entry.lock_battery == 90
        assert entry.uid is None
        assert entry.record_id is None
        assert entry.password is None
        assert entry.new_password is None
        assert entry.delete_date is None
        assert entry.key_id is None
        assert entry.accessory_battery is None
        assert entry.start_date is None
        assert entry.end_date is None

    def test_clear_all_carries_the_passcode_after_the_delete_date(self) -> None:
        entry = self._entry(8, bytes([26, 5, 11, 14, 23]) + bytes([4]) + b"5678")
        assert entry.delete_date is not None
        assert entry.password == "5678"

    def test_key_fob_without_battery_keeps_the_key_id(self) -> None:
        entry = self._entry(55, bytes([1, 2, 3, 4, 5, 6, 3]))
        assert entry.key_id == 3
        assert entry.accessory_battery is None

    def test_added_passcode_without_the_validity_window(self) -> None:
        entry = self._entry(93, bytes([4]) + b"1234")
        assert entry.password == "1234"
        assert entry.start_date is None
        assert entry.end_date is None


class TestLogRecordDispatch:
    """The lookup table is what replaced the SDK's flat switch — guard its shape."""

    def test_buckets_are_disjoint(self) -> None:
        buckets = [types for types, _ in log_record._TAIL_DECODERS_BY_BUCKET]
        assert sum(len(types) for types in buckets) == len(log_record._TAIL_DECODERS)
        assert set().union(*buckets) == set(log_record._TAIL_DECODERS)

    def test_unknown_record_type_decodes_the_header_only(self) -> None:
        unknown = next(t for t in range(256) if t not in log_record._TAIL_DECODERS)
        plain = _log_frame_plain(
            [bytes([unknown, 26, 5, 11, 14, 23, 7, 90]) + b"\x01\x02\x03\x04"], sequence=3
        )
        entries, _ = cmd.parse_operate_log_response(plain)
        assert entries[0].record_type == unknown
        assert entries[0].lock_battery == 90
        assert entries[0].password is None
        assert entries[0].uid is None
