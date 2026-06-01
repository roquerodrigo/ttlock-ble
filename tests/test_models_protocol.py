"""Coverage for models (LockVersion, SiteInfo, LockEvent, VirtualKey) and protocol edges."""

from __future__ import annotations

import pytest

from ttlock_ble import LockEvent, LockVersion, SiteInfo, VirtualKey
from ttlock_ble.crypto import crc_compute, hex_key_to_bytes, set_crc_func
from ttlock_ble.protocol import Frame, FrameReassembler
from ttlock_ble.protocol.constants import HEADER, TRAILER


class TestLockVersion:
    @pytest.mark.parametrize(
        ("pt", "sv", "sc", "expected"),
        [
            (5, 3, 7, 8),
            (10, 1, 0, 6),
            (5, 3, 2, 5),
            (5, 4, 0, 4),
            (5, 1, 0, 3),
            (11, 1, 0, 7),
            (99, 99, 99, 5),  # default fallthrough
        ],
    )
    def test_lock_type_switch(self, pt: int, sv: int, sc: int, expected: int) -> None:
        lv = LockVersion(protocolType=pt, protocolVersion=sv, scene=sc, groupId=0, orgId=0)
        assert lv.lock_type() == expected

    def test_parse_from_json_string(self) -> None:
        lv = LockVersion.parse('{"protocolType":5,"protocolVersion":3,"scene":2}')
        assert lv.protocolType == 5
        assert lv.groupId == 0  # default

    def test_parse_from_mapping(self) -> None:
        lv = LockVersion.parse(
            {
                "protocolType": "5",
                "protocolVersion": "3",
                "scene": "2",
                "groupId": "1",
                "orgId": "1",
            }
        )
        assert lv.orgId == 1


class TestSiteInfo:
    def test_from_payload_full(self) -> None:
        info = SiteInfo.from_payload(
            {
                "siteId": "3",
                "countryId": "44",
                "apiDomainName": "https://eu.example.com",
                "gatewayDomainName": "gw",
                "name": "EU",
            }
        )
        assert info.siteId == 3
        assert info.apiDomainName == "https://eu.example.com"
        assert info.name == "EU"

    def test_from_payload_defaults_domain(self) -> None:
        info = SiteInfo.from_payload({})
        assert info.apiDomainName == "https://servlet.ttlock.com"


class TestLockEvent:
    def test_status_enum_narrowing(self) -> None:
        event = LockEvent.from_payload(0x14, 1, bytes.fromhex("2c0102"))
        assert event.battery == 0x2C

    def test_unknown_status_kept_raw(self) -> None:
        event = LockEvent.from_payload(0x47, 99, b"\x00")
        assert event.status == 99

    def test_log_push_invalid_date_truncated_bytes(self) -> None:
        # 14-byte payload (date slice short) → _decode_timestamp returns None.
        payload = bytes.fromhex("2c000000006a0224a31a99010f30")
        event = LockEvent.from_payload(0x14, 1, payload)
        assert event.timestamp is None

    def test_six_byte_payload_only_battery(self) -> None:
        # cmd 0x14 but neither 3 nor >=15 bytes → only battery populated.
        event = LockEvent.from_payload(0x14, 1, bytes.fromhex("2c0102030405"))
        assert event.battery == 0x2C
        assert event.lock_state is None
        assert event.uid is None


class TestVirtualKey:
    def _payload(self) -> dict[str, object]:
        return {
            "keyId": "1",
            "lockId": "2",
            "lockMac": "E9:EF:A0:BD:22:1D",
            "lockAlias": "Door",
            "lockName": "DLock-XP",
            "lockVersion": {"protocolType": 5, "protocolVersion": 3, "scene": 2},
            "aesKeyStr": "2c,3d,23,5a,12,9c,74,0a,89,d5,0c,24,a5,3b,83,66",
            "lockKey": "375773543",
            "userType": "110301",
        }

    def test_from_cloud_round_trip(self) -> None:
        key = VirtualKey.from_cloud(self._payload(), uid=7)
        assert key.uid == 7
        assert key.is_admin() is True

    def test_to_dict_from_dict_round_trip(self) -> None:
        key = VirtualKey.from_cloud(self._payload(), uid=7)
        restored = VirtualKey.from_dict(key.to_dict())
        assert restored == key

    def test_to_int_default_on_empty(self) -> None:
        payload = self._payload()
        payload["lockFlagPos"] = ""
        key = VirtualKey.from_cloud(payload, uid=0)
        assert key.lockFlagPos == 0


class TestFrameProtocol:
    def test_legacy_frame_build_and_parse_round_trip(self) -> None:
        # protocol_type < 5 uses the short header layout.
        frame = Frame(
            protocol_type=1,
            sub_version=0,
            scene=0,
            group_id=0,
            sub_org=0,
            command=0x05,
            encrypt=0x00,
            data=b"\xde\xad",
        )
        wire = frame.build()
        body = wire[: -1 - len(TRAILER)]
        parsed = Frame.parse(body)
        assert parsed.command == 0x05
        assert parsed.data == b"\xde\xad"
        assert parsed.protocol_type == 1

    def test_parse_rejects_bad_header(self) -> None:
        with pytest.raises(ValueError, match="Invalid TTLock frame"):
            Frame.parse(b"\x00\x00\x05")

    def test_decrypt_data_passthrough_when_plain(self) -> None:
        frame = Frame(5, 3, 2, 1, 1, 0x05, 0xAA, b"plain")  # encrypt != ENCRYPT_AES
        assert frame.decrypt_data(b"\x00" * 16) == b"plain"

    def test_decrypt_data_aes_path(self) -> None:
        key = hex_key_to_bytes("2c,3d,23,5a,12,9c,74,0a,89,d5,0c,24,a5,3b,83,66")
        plain = Frame(5, 3, 2, 1, 1, 0x05, 0x00, b"hi").encrypt_data(key)
        # encrypt_data sets ENCRYPT_PLAIN (0x00); flip to AES to hit the decrypt branch.
        aes_frame = Frame(5, 3, 2, 1, 1, 0x05, 0x02, plain.data)
        assert aes_frame.decrypt_data(key) == b"hi"


class TestReassembler:
    def test_drops_noise_before_header(self) -> None:
        r = FrameReassembler()
        good = Frame(5, 3, 2, 1, 1, 0x05, 0x00, b"\x01").build()
        # Noise without a HEADER before the trailer is discarded on resync.
        noise = b"\x11\x22" + TRAILER
        frames = r.feed(noise + good)
        assert len(frames) == 1
        assert frames[0].command == 0x05

    def test_invalid_frame_between_markers_skipped(self) -> None:
        r = FrameReassembler()
        # HEADER followed by too-few bytes then TRAILER → Frame.parse raises, skipped.
        bad = HEADER + b"\x01" + TRAILER
        good = Frame(5, 3, 2, 1, 1, 0x05, 0x00, b"\x01").build()
        frames = r.feed(bad + good)
        assert [f.command for f in frames] == [0x05]


class TestCrypto:
    def test_set_crc_func_override(self) -> None:
        original = crc_compute(b"abc")
        set_crc_func(lambda _d: 0x42)
        try:
            assert crc_compute(b"abc") == 0x42
        finally:
            set_crc_func(_default_crc())
        assert crc_compute(b"abc") == original

    def test_hex_key_unrecognised_format_raises(self) -> None:
        with pytest.raises(ValueError, match="Unrecognised AES key format"):
            hex_key_to_bytes("not-a-key")

    def test_hex_key_continuous_form(self) -> None:
        assert len(hex_key_to_bytes("2c3d235a129c740a89d50c24a53b8366")) == 16


def _default_crc():
    from ttlock_ble.crypto import _table_crc

    return _table_crc
