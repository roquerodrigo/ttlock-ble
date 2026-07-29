"""Coverage for LockAdvertisement — the manufacturer-data state decoder."""

from __future__ import annotations

import pytest

from ttlock_ble import LockAdvertisement, LockState

MAC_TAIL = bytes.fromhex("1d22bda0efe9")
LOCK_MAC = "E9:EF:A0:BD:22:1D"


def v3_manufacturer_data(flags: int, battery: int = 87) -> tuple[int, bytes]:
    """Build a protocol 5.3 advertisement as bleak hands it over."""
    payload = bytes([2, flags, battery, 0, 0, 0, 0]) + MAC_TAIL
    return 0x0305, payload


def legacy_manufacturer_data(flags: int, battery: int = 42) -> tuple[int, bytes]:
    """Build an advertisement whose header does not match the 5.3 layout."""
    body = bytes([0, 0, 5, 4, 0, 3, flags, battery, 0]) + MAC_TAIL
    return 0x0102, body


class TestV3Layout:
    def test_decodes_unlocked_state(self) -> None:
        adv = LockAdvertisement.from_manufacturer_data(*v3_manufacturer_data(0x01))
        assert adv is not None
        assert adv.lock_state is LockState.UNLOCKED
        assert adv.protocol_type == 5
        assert adv.protocol_version == 3
        assert adv.scene == 2
        assert adv.battery == 87
        assert adv.lock_mac == LOCK_MAC

    def test_decodes_locked_state(self) -> None:
        adv = LockAdvertisement.from_manufacturer_data(*v3_manufacturer_data(0x00))
        assert adv is not None
        assert adv.lock_state is LockState.LOCKED
        assert adv.has_new_records is False
        assert adv.is_setting_mode is False

    @pytest.mark.parametrize(
        ("flags", "expected"),
        [
            (0x00, (False, False, False)),
            (0x01, (True, False, False)),
            (0x02, (False, True, False)),
            (0x04, (False, False, True)),
            (0x07, (True, True, True)),
            (0xFF, (True, True, True)),
        ],
    )
    def test_flag_bits(self, flags: int, expected: tuple[bool, bool, bool]) -> None:
        adv = LockAdvertisement.from_manufacturer_data(*v3_manufacturer_data(flags))
        assert adv is not None
        decoded = (
            adv.lock_state is LockState.UNLOCKED,
            adv.has_new_records,
            adv.is_setting_mode,
        )
        assert decoded == expected


class TestAlternateLayout:
    def test_reads_fields_from_the_shifted_offsets(self) -> None:
        adv = LockAdvertisement.from_manufacturer_data(*legacy_manufacturer_data(0x03))
        assert adv is not None
        assert adv.protocol_type == 5
        assert adv.protocol_version == 4
        assert adv.scene == 3
        assert adv.lock_state is LockState.UNLOCKED
        assert adv.has_new_records is True
        assert adv.battery == 42


class TestRejectedPayloads:
    def test_short_payload(self) -> None:
        assert LockAdvertisement.from_manufacturer_data(0x0305, b"\x02\x01\x50") is None

    @pytest.mark.parametrize("header", [0x1912, 0xFFFF])
    def test_firmware_update_mode(self, header: int) -> None:
        payload = bytes(6) + MAC_TAIL
        assert LockAdvertisement.from_manufacturer_data(header, payload) is None

    def test_protocol_older_than_v3(self) -> None:
        body = bytes([0, 0, 3, 1, 0, 2, 0x01, 90, 0]) + MAC_TAIL
        assert LockAdvertisement.from_manufacturer_data(0x0102, body) is None

    def test_v2s_family_has_no_state_byte(self) -> None:
        body = bytes([0, 0, 5, 1, 0, 0, 0x01, 90, 0]) + MAC_TAIL
        assert LockAdvertisement.from_manufacturer_data(0x0102, body) is None
