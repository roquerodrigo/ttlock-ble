"""TTLock V3 binary frame format: header, payload encryption, CRC, CRLF terminator."""

from __future__ import annotations

from .constants import ENCRYPT_AES, ENCRYPT_PLAIN, HEADER, TRAILER
from .frame import Frame
from .reassembler import FrameReassembler

__all__ = [
    "ENCRYPT_AES",
    "ENCRYPT_PLAIN",
    "HEADER",
    "TRAILER",
    "Frame",
    "FrameReassembler",
]
