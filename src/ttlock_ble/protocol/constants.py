"""On-the-wire constants for the V3 frame format."""

from __future__ import annotations

HEADER = bytes([0x7F, 0x5A])
TRAILER = bytes([0x0D, 0x0A])

ENCRYPT_PLAIN = 0xAA
ENCRYPT_AES = 0x02
