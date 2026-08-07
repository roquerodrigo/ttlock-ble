"""Crypto primitives reversed from libLockCore.so / AESUtil.

The decode table was extracted from arm64-v8a/libLockCore.so at offset
0x738 in the official DLock-XP 1.6.0 build. The byte fixtures below are
synthetic: they were produced with the reversed algorithms themselves and
pin the exact wire layout each primitive must keep decoding.
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

    def test_lock_handshake_payload_decrypts(self):
        # Golden `ttlock unlock` handshake ciphertext for a fixed test key.
        # Decrypts under the cloud-issued AES key into the standard
        # [cmd_echo=0x55][status=0x01][psFromLock(4 BE)] envelope.
        key = bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90")
        ct = bytes.fromhex("3ddfd6e40bb3b6661207b1c5c29c222d")
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
        # CHECK_USER_TIME frame body (without trailing CRC).
        body = bytes.fromhex(
            "7f5a0503020001000155aa20"
            "56ae48d08f38e9936f685bf5a332f55b"
            "bb67415bfddf32b713e4ca7fe13ec8c6"
        )
        assert crc_compute(body) == 0x1A


class TestCodecDecode:
    """Validates the reversed XOR algorithm against three passwords in the
    cloud's encoded wire format — each must produce a numeric string
    parseable as a 32-bit unsigned integer.
    """

    @pytest.mark.parametrize(
        ("encoded", "expected"),
        [
            # lockKey
            ("MTAzLDEwMSw5OSw5NywxMTEsMTAyLDEwMCw5OCw5NiwxMTAsNDE=", "0246813579"),
            # adminPwd
            (
                "MTExLDExMCwxMDgsMTA2LDEwNCwxMDIsMTA5LDEwNywxMDUsMTAzLDMz",
                "0135792468",
            ),
            # noKeyPwd
            ("MTU4LDE1MSwxNTksMTU3LDE1NSwxNTMsMTE1", "091357"),
        ],
    )
    def test_encoded_passwords(self, encoded: str, expected: str) -> None:
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
        s = "a1,b2,c3,d4,e5,f6,07,18,29,3a,4b,5c,6d,7e,8f,90"
        assert hex_key_to_bytes(s) == bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90")

    def test_continuous_hex(self):
        s = "000102030405060708090a0b0c0d0e0f"
        assert hex_key_to_bytes(s) == bytes(range(16))

    def test_rejects_wrong_part_count(self):
        with pytest.raises(ValueError):
            hex_key_to_bytes("01,02,03")

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            hex_key_to_bytes("")
