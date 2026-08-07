"""On-the-wire constants for the V3 frame format."""

from __future__ import annotations

HEADER = bytes([0x7F, 0x5A])
TRAILER = bytes([0x0D, 0x0A])

ENCRYPT_PLAIN = 0xAA
ENCRYPT_AES = 0x02

V3_HEADER_LEN = 12
LEGACY_HEADER_LEN = 6
V3_LENGTH_INDEX = 11
LEGACY_LENGTH_INDEX = 5
CRC_LEN = 1
