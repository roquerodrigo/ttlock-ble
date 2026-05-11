"""Crypto primitives reversed from libLockCore.so / AESUtil.

Reference values come from the official DLock-XP 1.6.0 build:
- decode table extracted from arm64-v8a/libLockCore.so at offset 0x738.
- Encoded passwords captured from a real cloud sync; the decoded
  numeric strings round-trip into Integer.valueOf() in the Java SDK.
"""

import pytest

from ttlock_ble.crypto import (
    aes_decrypt,
    aes_encrypt,
    codec_decode,
    crc_compute,
    decode_password,
    hex_key_to_bytes,
)


class TestAES:
    def test_roundtrip(self):
        key = bytes(range(16))
        data = b"the quick brown fox"
        assert aes_decrypt(aes_encrypt(data, key), key) == data

    def test_rejects_wrong_key_length(self):
        with pytest.raises(ValueError):
            aes_encrypt(b"hi", b"short")

    def test_real_lock_handshake_payload_decrypts(self):
        # Captured during a real `ttlock unlock` against an Apto. 2616 lock.
        # Decrypts under the cloud-issued AES key into the standard
        # [cmd_echo=0x55][status=0x01][psFromLock(4 BE)] envelope.
        key = bytes.fromhex("2c3d235a129c740a89d50c24a53b8366")
        ct = bytes.fromhex("196c2b37e4225e6876f02d781202bf5d")
        plain = aes_decrypt(ct, key)
        assert plain[0] == 0x55  # CHECK_USER_TIME echo
        assert plain[1] == 0x01  # SUCCESS


class TestCRC:
    def test_empty(self):
        assert crc_compute(b"") == 0

    def test_single_byte_indexes_table(self):
        # CRC([x]) = TABLE[x XOR 0] = TABLE[x]; first table byte is 0x00.
        assert crc_compute(b"\x00") == 0x00

    def test_known_frame(self):
        # Real CHECK_USER_TIME frame body (without trailing CRC).
        body = bytes.fromhex(
            "7f5a0503020001000155aa20"
            "bd0706cd9f13e00789aaad2a29863d24"
            "4ff35b8582497bcd198a44fef96d4f82"
        )
        assert crc_compute(body) == 0x41


class TestCodecDecode:
    """Validates the reversed XOR algorithm against three encoded passwords
    captured from the cloud — each must produce a numeric string parseable
    as a 32-bit unsigned integer.
    """

    @pytest.mark.parametrize(
        ("encoded", "expected"),
        [
            # lockKey
            ("MTAzLDEwMCw5Niw5OCw5Niw5NiwxMDAsOTgsOTksMTAwLDQx", "0375773543"),
            # adminPwd
            (
                "MTExLDEwNywxMDksMTA5LDEwNiwxMDgsMTEwLDEwOSwxMDYsMTAyLDMz",
                "0422531259",
            ),
            # noKeyPwd
            ("MTU4LDE1NywxNTgsMTUyLDE1MSwxNTIsMTE1", "030696"),
        ],
    )
    def test_real_passwords(self, encoded: str, expected: str) -> None:
        assert decode_password(encoded) == expected

    def test_short_field_passes_through(self) -> None:
        # Mirrors CommandUtil.U_checkUserTime guard `unlockKey.length() > 10`.
        assert decode_password("12345") == "12345"

    def test_empty_passes_through(self) -> None:
        assert decode_password("") == ""

    def test_codec_decode_too_short_returns_input(self) -> None:
        assert codec_decode(b"") == b""
        assert codec_decode(b"\x42") == b"\x42"


class TestHexKey:
    def test_comma_separated_hex(self):
        # Wire format used by the cloud's `aesKeyStr`.
        s = "2c,3d,23,5a,12,9c,74,0a,89,d5,0c,24,a5,3b,83,66"
        assert hex_key_to_bytes(s) == bytes.fromhex("2c3d235a129c740a89d50c24a53b8366")

    def test_continuous_hex(self):
        s = "000102030405060708090a0b0c0d0e0f"
        assert hex_key_to_bytes(s) == bytes(range(16))

    def test_rejects_wrong_part_count(self):
        with pytest.raises(ValueError):
            hex_key_to_bytes("01,02,03")

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            hex_key_to_bytes("")
