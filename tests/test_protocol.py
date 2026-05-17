"""Frame builder/parser, reassembly, and command payload layout."""

import pytest

from ttlock_ble import commands as cmd
from ttlock_ble.models import LockVersion
from ttlock_ble.protocol import (
    ENCRYPT_PLAIN,
    HEADER,
    TRAILER,
    Frame,
    FrameReassembler,
)


def _v3() -> LockVersion:
    """LockVersion matching the real DLock-XP unit used during testing."""
    return LockVersion(protocolType=5, protocolVersion=3, scene=2, groupId=1, orgId=1)


class TestFrame:
    def test_v3_header_layout(self):
        f = Frame.for_lock(_v3(), 0x55, b"AAAA", encrypt=ENCRYPT_PLAIN)
        wire = f.build()
        assert wire[0:2] == HEADER
        assert wire[2] == 5  # proto
        assert wire[3] == 3  # sub
        assert wire[4] == 2  # scene
        assert wire[5:7] == bytes([0, 1])  # groupId BE
        assert wire[7:9] == bytes([0, 1])  # orgId BE
        assert wire[9] == 0x55  # cmd
        assert wire[10] == 0xAA
        assert wire[11] == 4  # length
        assert wire[12:16] == b"AAAA"
        assert wire[-2:] == TRAILER

    def test_build_appends_crlf_terminator(self):
        wire = Frame.for_lock(_v3(), 0x14, b"SCIENER", encrypt=ENCRYPT_PLAIN).build()
        assert wire.endswith(TRAILER)

    def test_parse_roundtrip(self):
        f1 = Frame.for_lock(_v3(), 0x55, b"hello", encrypt=ENCRYPT_PLAIN)
        wire = f1.build()
        # parse() expects the frame body without the CRLF trailer.
        f2 = Frame.parse(wire[: -len(TRAILER)])
        assert f2.command == 0x55
        assert f2.data == b"hello"
        assert f2.protocol_type == 5

    def test_aes_encrypt_uses_app_command_marker(self):
        key = bytes(range(16))
        f = Frame.for_lock(_v3(), 0x55, b"x" * 17).encrypt_data(key)
        wire = f.build()
        # encrypt byte stays 0xAA (APP_COMMAND); ENCRY_AES_CBC=0x02 is
        # never on the wire even though the SDK declares the constant.
        assert wire[10] == 0xAA


class TestReassembler:
    def test_single_frame_in_one_chunk(self):
        wire = Frame.for_lock(_v3(), 0x55, b"hi", encrypt=ENCRYPT_PLAIN).build()
        ra = FrameReassembler()
        out = ra.feed(wire)
        assert len(out) == 1 and out[0].command == 0x55

    def test_split_across_two_chunks(self):
        wire = Frame.for_lock(_v3(), 0x47, b"hello", encrypt=ENCRYPT_PLAIN).build()
        ra = FrameReassembler()
        assert ra.feed(wire[:6]) == []
        out = ra.feed(wire[6:])
        assert len(out) == 1 and out[0].command == 0x47

    def test_two_frames_back_to_back(self):
        a = Frame.for_lock(_v3(), 0x55, b"a", encrypt=ENCRYPT_PLAIN).build()
        b = Frame.for_lock(_v3(), 0x47, b"bb", encrypt=ENCRYPT_PLAIN).build()
        ra = FrameReassembler()
        out = ra.feed(a + b)
        assert [f.command for f in out] == [0x55, 0x47]

    def test_resync_past_garbage(self):
        valid = Frame.for_lock(_v3(), 0x55, b"x", encrypt=ENCRYPT_PLAIN).build()
        ra = FrameReassembler()
        out = ra.feed(b"\xff\xff" + valid)
        assert len(out) == 1


class TestCommands:
    def test_check_user_time_default_payload_layout(self):
        p = cmd.payload_check_user_time()
        assert len(p) == 17
        # Default sentinel start date "0001311400" → 5 BCD bytes
        assert p[0:5] == bytes.fromhex("0001311400")
        # uid=0 default
        assert p[13:17] == bytes(4)

    def test_check_user_time_response_extracts_ps_from_lock(self):
        # Captured plaintext from a real run: [0x55, 0x01, ps(4), uniqueid(2)]
        plain = bytes.fromhex("55011db78a8f")
        assert cmd.parse_check_user_time_response(plain) == 0x1DB78A8F

    def test_check_user_time_response_raises_on_failure(self):
        with pytest.raises(RuntimeError):
            cmd.parse_check_user_time_response(bytes([0x55, 0x00, 0x08]))

    def test_unlock_payload_sums_ps_and_key(self):
        p = cmd.payload_unlock(ps_from_lock=10, unlock_key="20", ts_ms=1_000_000)
        assert p[0:4] == (30).to_bytes(4, "big")
        assert p[4:8] == (1000).to_bytes(4, "big")

    def test_unlock_payload_overflow_wraps(self):
        p = cmd.payload_unlock(ps_from_lock=0xFFFFFFFF, unlock_key=2, ts_ms=1_000_000)
        assert p[0:4] == (1).to_bytes(4, "big")  # mod 2**32

    def test_check_random_payload_is_4byte_sum(self):
        p = cmd.payload_check_random(0x100, "1")
        assert p == (0x101).to_bytes(4, "big")

    def test_query_state_payload_is_sciener_literal(self):
        assert cmd.payload_query_state() == b"SCIENER"

    def test_parse_response_status_envelope(self):
        echo, status, data = cmd.parse_response_status(bytes.fromhex("47012a0000"))
        assert echo == 0x47 and status == 0x01 and data == b"\x2a\x00\x00"

    def test_parse_lock_status_locked(self):
        # Real captured response; byte 0 of payload is battery, byte 1 is state.
        from ttlock_ble import LockState

        plain = bytes.fromhex("14012d0002")
        result = cmd.parse_lock_status(plain)
        assert result is LockState.LOCKED
        assert result == cmd.LOCKED  # backwards-compat alias

    def test_parse_lock_status_unknown_byte_returns_none(self):
        # Status byte 5 isn't a valid LockState member.
        plain = bytes.fromhex("14012d0502")
        assert cmd.parse_lock_status(plain) is None

    def test_parse_lock_status_failed_response_returns_none(self):
        plain = bytes.fromhex("140008")
        assert cmd.parse_lock_status(plain) is None

    def test_parse_state_battery(self):
        plain = bytes.fromhex("14012d0002")
        assert cmd.parse_state_battery(plain) == 45

    def test_time_calibrate_payload_is_decimal_not_bcd(self):
        import datetime as dt

        when = dt.datetime(2026, 5, 11, 14, 23, 7, tzinfo=dt.UTC)
        payload = cmd.payload_time_calibrate(when)
        # 6 bytes: yy MM dd HH mm ss, each byte is the literal decimal value.
        # Year 2026 → byte 26 (0x1A), NOT 0x26 (which BCD would emit).
        assert payload == bytes([26, 5, 11, 14, 23, 7])
        assert payload[0] == 0x1A

    def test_time_calibrate_default_uses_now(self):
        payload = cmd.payload_time_calibrate()
        assert len(payload) == 6
        # Year byte should be in the plausible range [25, 99] for a current run.
        assert 25 <= payload[0] <= 99


class TestAutoLock:
    def test_search_payload_is_one_byte(self):
        assert cmd.payload_auto_lock_search() == b"\x01"

    def test_set_payload_is_op_plus_uint16_be(self):
        assert cmd.payload_auto_lock_set(300) == bytes([0x02, 0x01, 0x2C])
        assert cmd.payload_auto_lock_set(0) == bytes([0x02, 0x00, 0x00])

    def test_set_payload_rejects_out_of_range(self):
        import pytest

        with pytest.raises(ValueError):
            cmd.payload_auto_lock_set(-1)
        with pytest.raises(ValueError):
            cmd.payload_auto_lock_set(70000)

    def test_parse_search_response(self):
        # battery=45, op=SEARCH, value=300, plus min/max appended
        plain = bytes([0x36, 0x01]) + bytes([45, 0x01, 0x01, 0x2C, 0x00, 0x05, 0x0E, 0x10])
        seconds, battery = cmd.parse_auto_lock_response(plain)
        assert seconds == 300
        assert battery == 45

    def test_parse_modify_response_returns_minus_one_seconds(self):
        plain = bytes([0x36, 0x01]) + bytes([45, 0x02])
        seconds, battery = cmd.parse_auto_lock_response(plain)
        assert seconds == -1
        assert battery == 45


class TestPasscode:
    def test_add_permanent_layout(self):
        from ttlock_ble.constants import KeyboardPwdType

        payload = cmd.payload_passcode_add(int(KeyboardPwdType.PERMANENT), "1234")
        # op=2, type=1, len=4, "1234" ascii (0x31..0x34), 5-byte start date (no end)
        assert payload[0] == 0x02
        assert payload[1] == 0x01
        assert payload[2] == 0x04
        assert payload[3:7] == b"1234"
        assert len(payload) == 12

    def test_add_period_includes_end_date(self):
        from ttlock_ble.constants import KeyboardPwdType

        payload = cmd.payload_passcode_add(int(KeyboardPwdType.PERIOD), "9876")
        assert payload[0] == 0x02
        assert payload[1] == 0x03
        # 1 (op) + 1 (type) + 1 (len) + 4 (code) + 5 (start) + 5 (end)
        assert len(payload) == 17

    def test_add_rejects_short_code(self):
        import pytest

        with pytest.raises(ValueError):
            cmd.payload_passcode_add(1, "12")

    def test_add_rejects_non_digit_code(self):
        import pytest

        with pytest.raises(ValueError):
            cmd.payload_passcode_add(1, "12ab")

    def test_delete_layout(self):
        payload = cmd.payload_passcode_delete(1, "5678")
        assert payload == bytes([0x03, 0x01, 0x04]) + b"5678"

    def test_clear_payload(self):
        assert cmd.payload_passcode_clear() == b"\x01"


class TestOperationLog:
    def test_request_payload(self):
        assert cmd.payload_operate_log_request() == bytes([0xFF, 0xFF])
        assert cmd.payload_operate_log_request(42) == bytes([0x00, 0x2A])

    def test_parse_empty_log(self):
        # status=SUCCESS, total_len=0
        plain = bytes([0x25, 0x01, 0x00, 0x00])
        entries, last_seq = cmd.parse_operate_log_response(plain)
        assert entries == []
        assert last_seq == 0

    def test_parse_keypad_unlock_record(self):
        from ttlock_ble.constants import LogOperate

        # envelope: cmd_echo=0x25, status=0x01
        # data:     totalLen(2) + sequence(2) + recLen + recordType + date(6) + battery
        #           + pwdLen + pwd + newPwdLen + newPwd
        #           = 2 + 2 + 1 + 1 + 6 + 1 + 1 + 4 + 1 + 0 = 19 bytes
        record = (
            bytes([LogOperate.KEYBOARD_PASSWORD_UNLOCK])  # type
            + bytes([26, 5, 11, 14, 23, 7])  # 2026-05-11 14:23:07
            + bytes([45])  # battery
            + bytes([4])  # pwd_len
            + b"1234"  # pwd
            + bytes([0])  # new_pwd_len
        )
        rec_len = len(record)
        plain = (
            bytes([0x25, 0x01])  # envelope
            + (rec_len + 5).to_bytes(2, "big")  # total content len
            + (1).to_bytes(2, "big")  # sequence
            + bytes([rec_len])  # record length prefix
            + record
        )
        entries, last_seq = cmd.parse_operate_log_response(plain)
        assert last_seq == 1
        assert len(entries) == 1
        e = entries[0]
        assert e.record_type == LogOperate.KEYBOARD_PASSWORD_UNLOCK
        assert e.password == "1234"
        assert e.lock_battery == 45
        assert e.operate_date == "20260511142307"

    def _wrap(self, record_body: bytes, *, sequence: int = 1) -> bytes:
        rec_len = len(record_body)
        return (
            bytes([0x25, 0x01])
            + (rec_len + 5).to_bytes(2, "big")
            + sequence.to_bytes(2, "big")
            + bytes([rec_len])
            + record_body
        )

    def _header(self, record_type: int, *, battery: int = 50) -> bytes:
        # record_type + YYMMDDhhmmss + battery — fields the parser strips before
        # handing the tail to `_decode_log_record`.
        return bytes([record_type]) + bytes([26, 5, 17, 12, 0, 0]) + bytes([battery])

    def test_parse_operate_ble_lock_record(self):
        from ttlock_ble.constants import LogOperate

        # record_type=26 (OPERATE_BLE_LOCK) was previously decoded as UNKNOWN.
        record = (
            self._header(LogOperate.OPERATE_BLE_LOCK)
            + (0xDEADBEEF).to_bytes(4, "big")
            + (0x6A0224A3).to_bytes(4, "big")
        )
        entries, _ = cmd.parse_operate_log_response(self._wrap(record))
        e = entries[0]
        assert e.record_type == LogOperate.OPERATE_BLE_LOCK
        assert e.uid == 0xDEADBEEF
        assert e.record_id == 0x6A0224A3

    def test_parse_remote_control_key_record(self):
        from ttlock_ble.constants import LogOperate

        # record_type=37 carries uid+rid+keyId.
        record = (
            self._header(LogOperate.REMOTE_CONTROL_KEY)
            + (1).to_bytes(4, "big")
            + (2).to_bytes(4, "big")
            + bytes([7])
        )
        entries, _ = cmd.parse_operate_log_response(self._wrap(record))
        e = entries[0]
        assert e.uid == 1
        assert e.record_id == 2
        assert e.key_id == 7

    def test_parse_wireless_key_fob_record(self):
        from ttlock_ble.constants import LogOperate

        # record_type=55 carries MAC (LE) + keyId + accessory_battery.
        mac_le = bytes.fromhex("1d22bda0efe9")
        record = self._header(LogOperate.WIRELESS_KEY_FOB) + mac_le + bytes([3, 88])
        entries, _ = cmd.parse_operate_log_response(self._wrap(record))
        e = entries[0]
        assert e.password == "e9:ef:a0:bd:22:1d"
        assert e.key_id == 3
        assert e.accessory_battery == 88

    def test_parse_wireless_key_pad_has_battery_but_no_key_id(self):
        from ttlock_ble.constants import LogOperate

        # record_type=56 carries MAC + accessory_battery (no key_id byte).
        mac_le = bytes.fromhex("aabbccddeeff")
        record = self._header(LogOperate.WIRELESS_KEY_PAD) + mac_le + bytes([42])
        entries, _ = cmd.parse_operate_log_response(self._wrap(record))
        e = entries[0]
        assert e.password == "ff:ee:dd:cc:bb:aa"
        assert e.accessory_battery == 42
        assert e.key_id is None

    def test_parse_log_record_type_is_enum_member(self):
        from ttlock_ble.constants import LogOperate

        record = (
            self._header(LogOperate.MOBILE_UNLOCK) + (1).to_bytes(4, "big") + (2).to_bytes(4, "big")
        )
        entries, _ = cmd.parse_operate_log_response(self._wrap(record))
        assert entries[0].record_type is LogOperate.MOBILE_UNLOCK

    def test_parse_log_record_unknown_type_falls_back_to_int(self):
        # byte 200 isn't defined in LogOperate — must surface as raw int.
        record = self._header(200)
        entries, _ = cmd.parse_operate_log_response(self._wrap(record))
        assert entries[0].record_type == 200
        assert not hasattr(entries[0].record_type, "name")

    def test_parse_add_passcode_record_carries_validity_window(self):
        from ttlock_ble.constants import LogOperate

        # record_type=93 (ADD_PASSCODE_SUCCESSFULLY) carries pwd + start(5) + end(5).
        pwd = b"246810"
        record = (
            self._header(LogOperate.ADD_PASSCODE_SUCCESSFULLY)
            + bytes([len(pwd)])
            + pwd
            + bytes([26, 5, 17, 12, 0])  # start: 2026-05-17 12:00
            + bytes([26, 5, 18, 12, 0])  # end:   2026-05-18 12:00
        )
        entries, _ = cmd.parse_operate_log_response(self._wrap(record))
        e = entries[0]
        assert e.password == "246810"
        assert e.start_date == "202605171200"
        assert e.end_date == "202605181200"


class TestLockVersion:
    def test_lock_type_v3(self):
        # protocolType=5, protocolVersion=3 → V3 (lockType 5)
        assert _v3().lock_type() == 5

    def test_parse_from_dict(self):
        lv = LockVersion.parse(
            {"protocolType": 5, "protocolVersion": 3, "scene": 2, "groupId": 1, "orgId": 1}
        )
        assert lv.protocolType == 5

    def test_parse_from_json_string(self):
        lv = LockVersion.parse(
            '{"protocolType":5,"protocolVersion":3,"scene":2,"groupId":1,"orgId":1}'
        )
        assert lv.scene == 2
