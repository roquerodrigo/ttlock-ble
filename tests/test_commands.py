"""Pure payload builders and response parsers in `commands.py` (byte-level)."""

from __future__ import annotations

import datetime as dt
from typing import TYPE_CHECKING

import pytest

from ttlock_ble import commands as cmd
from ttlock_ble.commands import log_record
from ttlock_ble.constants import KeyboardPwdType, LockState, LockVolume
from ttlock_ble.models import CyclicSchedule

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

    def test_passcode_list_sequence_is_uint16_be(self) -> None:
        assert cmd.payload_passcode_list(0) == b"\x00\x00"
        assert cmd.payload_passcode_list(300) == (300).to_bytes(2, "big")

    def test_operate_log_request(self) -> None:
        assert cmd.payload_operate_log_request() == b"\xff\xff"
        assert cmd.payload_operate_log_request(5) == b"\x00\x05"

    def test_fingerprint_list_layout(self) -> None:
        assert cmd.payload_fingerprint_list(0) == bytes([0x06, 0x00, 0x00])
        assert cmd.payload_fingerprint_list(300) == bytes([0x06, 0x01, 0x2C])


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


def _fingerprint_response(
    *, position: int, fingerprint_id: bytes, slot: int, start: bytes, end: bytes
) -> bytes:
    """Build a full CMD 0x06/0x06 SUCCESS response matching the confirmed wire layout."""
    data = (
        bytes([0x64, 0x06])
        + position.to_bytes(2, "big")
        + fingerprint_id
        + slot.to_bytes(2, "big")
        + start
        + end
    )
    assert len(data) == 20
    return bytes([0x06, cmd.RESPONSE_SUCCESS]) + data


class TestFingerprintList:
    def test_end_of_list_returns_none(self) -> None:
        # Real capture from an empty enrollment: SUCCESS status,
        # data = [battery][op_echo=0x06][0xFF][0xFF].
        plain = bytes([0x06, cmd.RESPONSE_SUCCESS, 0x64, 0x06, 0xFF, 0xFF])
        assert cmd.parse_fingerprint_list_response(plain) is None

    def test_end_of_list_ignores_the_battery_value(self) -> None:
        plain = bytes([0x06, cmd.RESPONSE_SUCCESS, 0x00, 0x06, 0xFF, 0xFF])
        assert cmd.parse_fingerprint_list_response(plain) is None

    def test_permanent_entry_with_explicit_start(self) -> None:
        plain = _fingerprint_response(
            position=1,
            fingerprint_id=bytes([0x00, 0x00, 0x00, 0x2A]),
            slot=3,
            start=bytes([26, 3, 1, 8, 0]),
            end=cmd.END_DATE_SENTINEL,
        )
        entry = cmd.parse_fingerprint_list_response(plain)
        assert entry is not None
        assert entry.fingerprint_id == bytes([0x00, 0x00, 0x00, 0x2A])
        assert entry.slot == 3
        assert entry.start_date == dt.datetime(2026, 3, 1, 8, 0)  # noqa: DTZ001
        assert entry.end_date is None
        assert entry.is_permanent
        assert entry.has_explicit_start

    def test_timed_entry_with_sentinel_start(self) -> None:
        plain = _fingerprint_response(
            position=2,
            fingerprint_id=bytes([0x00, 0x00, 0x00, 0x2B]),
            slot=4,
            start=cmd.START_DATE_SENTINEL,
            end=bytes([26, 12, 31, 23, 59]),
        )
        entry = cmd.parse_fingerprint_list_response(plain)
        assert entry is not None
        assert entry.start_date is None
        assert entry.end_date == dt.datetime(2026, 12, 31, 23, 59)  # noqa: DTZ001
        assert not entry.is_permanent
        assert not entry.has_explicit_start

    def test_entry_position_does_not_leak_into_fingerprint_id(self) -> None:
        # Regression: reading the layout without the leading battery byte
        # leaked `position` into fingerprint_id's first byte on real hardware.
        plain = _fingerprint_response(
            position=7,
            fingerprint_id=bytes([0xAA, 0xBB, 0xCC, 0xDD]),
            slot=3,
            start=cmd.START_DATE_SENTINEL,
            end=cmd.END_DATE_SENTINEL,
        )
        entry = cmd.parse_fingerprint_list_response(plain)
        assert entry is not None
        assert entry.fingerprint_id == bytes([0xAA, 0xBB, 0xCC, 0xDD])

    def test_credential_not_found_raises_clearly(self) -> None:
        plain = bytes([0x06, cmd.RESPONSE_FAILED, 0x1A])
        with pytest.raises(RuntimeError, match="credential not found"):
            cmd.parse_fingerprint_list_response(plain)

    def test_other_failure_raises(self) -> None:
        plain = bytes([0x06, cmd.RESPONSE_FAILED, 0x02])
        with pytest.raises(RuntimeError, match="FAILED"):
            cmd.parse_fingerprint_list_response(plain)

    def test_short_success_payload_raises(self) -> None:
        plain = bytes([0x06, cmd.RESPONSE_SUCCESS, 0x06, 0x00, 0x01])
        with pytest.raises(ValueError, match="too short"):
            cmd.parse_fingerprint_list_response(plain)

    def test_sentinel_constants_decode_to_the_documented_dates(self) -> None:
        from ttlock_ble.commands.encoding import decode_date5

        assert decode_date5(cmd.START_DATE_SENTINEL) == dt.datetime(2000, 1, 1, 0, 0)  # noqa: DTZ001
        assert decode_date5(cmd.END_DATE_SENTINEL) == dt.datetime(2099, 1, 1, 0, 0)  # noqa: DTZ001


class TestDeviceProperties:
    """Exact plaintexts confirmed on real hardware - used verbatim, not reconstructed."""

    def test_payload_is_a_single_step_byte(self) -> None:
        assert cmd.payload_device_property(1) == bytes([0x01])
        assert cmd.payload_device_property(6) == bytes([0x06])

    def test_step1_model_variant(self) -> None:
        plain = bytes.fromhex("9001534e3437385f5056353300")
        assert cmd.parse_device_property_string(plain) == "SN478_PV53"

    def test_step2_hardware_revision(self) -> None:
        plain = bytes.fromhex("9001312e3200")
        assert cmd.parse_device_property_string(plain) == "1.2"

    def test_step3_firmware_version(self) -> None:
        plain = bytes.fromhex("9001362e342e34332e32343035323900")
        assert cmd.parse_device_property_string(plain) == "6.4.43.240529"

    def test_step4_hardware_id(self) -> None:
        plain = bytes.fromhex("9001326236656161653300")
        assert cmd.parse_device_property_string(plain) == "2b6eaae3"

    def test_step5_mac_address_is_byte_reversed(self) -> None:
        plain = bytes.fromhex("9001bc0d3d554476")
        assert cmd.parse_device_property_mac(plain) == "76:44:55:3D:0D:BC"

    def test_step6_clock_time(self) -> None:
        plain = bytes.fromhex("90011a081d172f34")
        assert cmd.parse_device_property_clock(plain) == dt.datetime(  # noqa: DTZ001 -- lock RTC is naive
            2026, 8, 29, 23, 47, 52
        )

    def test_step7_unrecognized_raises(self) -> None:
        plain = bytes([0x90, cmd.RESPONSE_FAILED, 0x19])
        with pytest.raises(RuntimeError, match="unrecognized device property step"):
            cmd.parse_device_property_string(plain)

    def test_other_failure_raises(self) -> None:
        plain = bytes([0x90, cmd.RESPONSE_FAILED, 0xFF])
        with pytest.raises(RuntimeError, match="FAILED"):
            cmd.parse_device_property_string(plain)

    def test_clock_invalid_date_raises(self) -> None:
        plain = bytes([0x90, cmd.RESPONSE_SUCCESS, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        with pytest.raises(ValueError, match="not a valid date"):
            cmd.parse_device_property_clock(plain)


def _passcode_item(*, pwd_type: int, new_pwd: bytes, pwd: bytes, trailer: bytes) -> bytes:
    """Build one `[item_len][pwd_type][new_pwd_len][new_pwd][pwd_len][pwd][trailer]` item.

    Synthetic, structurally derived from the confirmed wire layout - used
    only for error/edge cases a real capture can't provide (a malformed
    response, an untested day-of-week). The happy-path fixtures below use
    real captured bytes instead - see `_real_plain`.
    """
    body = bytes([pwd_type, len(new_pwd)]) + new_pwd + bytes([len(pwd)]) + pwd + trailer
    return bytes([len(body)]) + body


def _passcode_response(*, next_sequence: int, item: bytes = b"") -> bytes:
    header = b"\x00\x00" + next_sequence.to_bytes(2, "big")  # header[0:2] purpose unconfirmed
    return bytes([cmd.CMD_GET_PASSCODES, cmd.RESPONSE_SUCCESS]) + header + item


_PERMANENT_START_SENTINEL = bytes([0x00, 0x01, 0x01, 0x00, 0x00])  # 2000-01-01 00:00


def _real_plain(data_hex: str) -> bytes:
    """Wrap a real captured `data` hex string (echo=0x07, status=SUCCESS) into a full plaintext."""
    return bytes([cmd.CMD_GET_PASSCODES, cmd.RESPONSE_SUCCESS]) + bytes.fromhex(data_hex)


class TestPasscodeList:
    """The happy-path fixtures below are real CMD 0x07 captures from a physical
    lock, pasted verbatim as `data_hex` (the `data` portion of a SUCCESS
    response, after cmd_echo/status). Error-path tests further down remain
    synthetic, since no real capture exercises a malformed response.
    """

    def test_period_entry(self) -> None:
        plain = _real_plain("002000011d0308313939303731383008313939303731383000010100001b09061100")
        entry, next_seq = cmd.parse_passcode_list_response(plain)
        assert entry is not None
        assert entry.passcode == "19907180"
        assert entry.pwd_type == KeyboardPwdType.PERIOD
        assert not entry.is_permanent
        assert entry.start_date == dt.datetime(2000, 1, 1, 0, 0)  # noqa: DTZ001 -- lock RTC is naive
        assert entry.end_date == dt.datetime(2027, 9, 6, 17, 0)  # noqa: DTZ001 -- lock RTC is naive
        assert entry.cyclic_schedule is None
        assert next_seq == 1

    def test_permanent_entry(self) -> None:
        plain = _real_plain("001b015018010836303932303534390836303932303534390001010000")
        entry, next_seq = cmd.parse_passcode_list_response(plain)
        assert entry is not None
        assert entry.passcode == "60920549"
        assert entry.pwd_type == KeyboardPwdType.PERMANENT
        assert entry.is_permanent
        assert entry.start_date == dt.datetime(2000, 1, 1, 0, 0)  # noqa: DTZ001 -- lock RTC is naive
        assert entry.end_date is None
        assert entry.cyclic_schedule is None
        assert next_seq == 336

    @pytest.mark.parametrize(
        ("data_hex", "passcode", "day_or_preset", "start_hour", "duration_hours"),
        [
            (
                "001f00021c040935323839353833353909353238393538333539000101110004c0",
                "528958359",
                "Sunday",
                17,
                1,
            ),
            (
                "001f00031c04093335383230333139350933353832303331393500010111000400",
                "358203195",
                "Daily",
                17,
                1,
            ),
            (
                "001f00041c040934363539333333353309343635393333333533000101110003e8",
                "465933353",
                "Weekend",
                17,
                1,
            ),
            (
                "001f00051c040937303235373538363709373032353735383637000101110004a8",
                "702575867",
                "Saturday",
                17,
                1,
            ),
            (
                "001f00061c04093636383230353130320936363832303531303200010111000430",
                "668205102",
                "Monday",
                17,
                1,
            ),
            (
                "001f00071c04093439383133383331340934393831333833313400010110000419",
                "498138314",
                "Workdays",
                16,
                2,
            ),
            (
                "001f00081c04093430383634393633320934303836343936333200010111000449",
                "408649632",
                "Tuesday",
                17,
                2,
            ),
            (
                "001f00091c0409363837353438353136093638373534383531360001010a0003f1",
                "687548516",
                "Weekend",
                10,
                10,
            ),
        ],
    )
    def test_cyclic_entry_real_captures(
        self,
        data_hex: str,
        passcode: str,
        day_or_preset: str,
        start_hour: int,
        duration_hours: int,
    ) -> None:
        # The two Weekend rows (duration 1 and 10) are the "two independent
        # duration tests" that confirmed its base value exactly.
        entry, _ = cmd.parse_passcode_list_response(_real_plain(data_hex))
        assert entry is not None
        assert entry.passcode == passcode
        assert entry.pwd_type == KeyboardPwdType.CIRCLE
        assert entry.start_date is None
        assert entry.end_date is None
        assert entry.cyclic_schedule == CyclicSchedule(
            day_or_preset=day_or_preset,
            start_hour=start_hour,
            start_minute=0,
            duration_hours=duration_hours,
        )

    def test_end_of_list_is_a_bare_two_byte_response(self) -> None:
        # Confirmed on real hardware: the terminal response is `0000` -
        # too short to even carry next_sequence, not a 4-byte header
        # followed by an empty item.
        entry, next_seq = cmd.parse_passcode_list_response(_real_plain("0000"))
        assert entry is None
        assert next_seq == 0

    @pytest.mark.parametrize(
        ("day_or_preset", "base_selector"),
        [
            ("Daily", 0),
            ("Workdays", 24),
            ("Monday", 48),
            ("Tuesday", 72),
            ("Wednesday", 96),
            ("Thursday", 120),
            ("Friday", 144),
            ("Saturday", 168),
            ("Sunday", 192),
            ("Weekend", 232),
        ],
    )
    def test_cyclic_reverse_inference_every_base_selector(
        self, day_or_preset: str, base_selector: int
    ) -> None:
        """Synthetic - exercises the inference formula for every known base,
        including Wednesday/Thursday/Friday, which no real capture has ever
        exercised (see the module docstring and the source-audit test below).
        """
        duration_hours = 3
        low_byte = base_selector + duration_hours - 1
        trailer = bytes(
            [0x00, 0x01, 0x01, 8, 30, 0x04, low_byte]
        )  # trailer[5]=4, per real captures
        item = _passcode_item(
            pwd_type=int(KeyboardPwdType.CIRCLE), new_pwd=b"9988", pwd=b"9988", trailer=trailer
        )
        entry, _ = cmd.parse_passcode_list_response(_passcode_response(next_sequence=0, item=item))
        assert entry is not None
        assert entry.cyclic_schedule == CyclicSchedule(
            day_or_preset=day_or_preset,
            start_hour=8,
            start_minute=30,
            duration_hours=duration_hours,
        )

    def test_new_pwd_differing_from_pwd_exposes_new_pwd(self) -> None:
        # Synthetic: "identical when the passcode hasn't been changed since
        # creation" - no real capture has shown the two differ, so this
        # covers the case on paper; `passcode` follows new_pwd.
        item = _passcode_item(
            pwd_type=int(KeyboardPwdType.PERMANENT),
            new_pwd=b"999999",
            pwd=b"111111",
            trailer=_PERMANENT_START_SENTINEL,
        )
        entry, _ = cmd.parse_passcode_list_response(_passcode_response(next_sequence=0, item=item))
        assert entry is not None
        assert entry.passcode == "999999"

    def test_final_entry_can_carry_next_sequence_zero(self) -> None:
        # Synthetic: no real capture ended this way (the real end-of-list
        # was always the bare 2-byte marker), but the protocol description
        # allows it, so the parser must handle it without special-casing.
        item = _passcode_item(
            pwd_type=int(KeyboardPwdType.PERMANENT),
            new_pwd=b"1234",
            pwd=b"1234",
            trailer=_PERMANENT_START_SENTINEL,
        )
        entry, next_seq = cmd.parse_passcode_list_response(
            _passcode_response(next_sequence=0, item=item)
        )
        assert entry is not None
        assert next_seq == 0

    def test_short_item_with_full_header_is_treated_as_end_of_list(self) -> None:
        # Synthetic: a full 4-byte header but too little data for an item -
        # never seen in a real capture (the real end-of-list is the bare
        # 2-byte marker instead), but handled leniently rather than raising.
        plain = bytes([cmd.CMD_GET_PASSCODES, cmd.RESPONSE_SUCCESS, 0x00, 0x00, 0x00, 0x03])
        entry, next_seq = cmd.parse_passcode_list_response(plain)
        assert entry is None
        assert next_seq == 3

    def test_failure_status_raises(self) -> None:
        plain = bytes([cmd.CMD_GET_PASSCODES, cmd.RESPONSE_FAILED, 0xFF])
        with pytest.raises(RuntimeError, match="FAILED"):
            cmd.parse_passcode_list_response(plain)

    def test_short_header_is_treated_as_end_of_list(self) -> None:
        # Any data shorter than a full 4-byte header is end-of-list, not an
        # error - matches the confirmed bare 2-byte terminal response.
        plain = bytes([cmd.CMD_GET_PASSCODES, cmd.RESPONSE_SUCCESS, 0x00])
        entry, next_seq = cmd.parse_passcode_list_response(plain)
        assert entry is None
        assert next_seq == 0

    def test_unknown_pwd_type_raises(self) -> None:
        item = _passcode_item(pwd_type=0x09, new_pwd=b"1234", pwd=b"1234", trailer=b"")
        with pytest.raises(ValueError, match="unknown pwd_type"):
            cmd.parse_passcode_list_response(_passcode_response(next_sequence=0, item=item))

    def test_pwd_type_with_no_confirmed_layout_raises(self) -> None:
        # KeyboardPwdType.COUNT (2) is a recognized enum member, but no
        # trailer layout for it has ever been confirmed - must not guess.
        item = _passcode_item(
            pwd_type=int(KeyboardPwdType.COUNT), new_pwd=b"1234", pwd=b"1234", trailer=b""
        )
        with pytest.raises(ValueError, match="no confirmed layout"):
            cmd.parse_passcode_list_response(_passcode_response(next_sequence=0, item=item))

    def test_trailer_too_short_raises(self) -> None:
        item = _passcode_item(
            pwd_type=int(KeyboardPwdType.PERMANENT),
            new_pwd=b"1234",
            pwd=b"1234",
            trailer=b"\x00\x01",
        )
        with pytest.raises(ValueError, match="too short for its trailer"):
            cmd.parse_passcode_list_response(_passcode_response(next_sequence=0, item=item))

    def test_every_possible_low_byte_resolves_to_some_base(self) -> None:
        # Daily's base is 0, the floor of every known selector, so no
        # low_byte value (0-255) can ever fail to resolve to *some* named
        # preset/day - there is no "unrecognized base_selector" to reject.
        for low_byte in (0, 1, 23, 255):
            trailer = bytes([0x00, 0x01, 0x01, 8, 0, 0x04, low_byte])
            item = _passcode_item(
                pwd_type=int(KeyboardPwdType.CIRCLE), new_pwd=b"9988", pwd=b"9988", trailer=trailer
            )
            entry, _ = cmd.parse_passcode_list_response(
                _passcode_response(next_sequence=0, item=item)
            )
            assert entry is not None
            assert entry.cyclic_schedule is not None

    def test_invalid_permanent_date_raises(self) -> None:
        item = _passcode_item(
            pwd_type=int(KeyboardPwdType.PERMANENT),
            new_pwd=b"1234",
            pwd=b"1234",
            trailer=bytes([0x00, 0xFF, 0xFF, 0x00, 0x00]),
        )
        with pytest.raises(ValueError, match="not a valid date"):
            cmd.parse_passcode_list_response(_passcode_response(next_sequence=0, item=item))

    def test_new_pwd_length_past_the_payload_raises(self) -> None:
        # [item_length][pwd_type][new_pwd_length=9] followed by a single digit.
        item = bytes([0x04, int(KeyboardPwdType.PERMANENT), 0x09]) + b"1"
        with pytest.raises(ValueError, match="too short for its passcode"):
            cmd.parse_passcode_list_response(_passcode_response(next_sequence=0, item=item))


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
