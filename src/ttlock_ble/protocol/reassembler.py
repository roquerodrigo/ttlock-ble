"""FrameReassembler: buffer BLE notifications until a complete frame has arrived."""

from __future__ import annotations

from .constants import (
    CRC_LEN,
    HEADER,
    TRAILER,
    V3_HEADER_LEN,
    V3_LENGTH_INDEX,
)
from .frame import Frame

MIN_PROTOCOL_TYPE = 5


def _declared_frame_len(buf: bytes) -> int | None:
    """Total wire length of the frame at the head of `buf`, or None if not yet known."""
    if len(buf) <= V3_LENGTH_INDEX:
        return None
    return V3_HEADER_LEN + buf[V3_LENGTH_INDEX] + CRC_LEN + len(TRAILER)


class FrameReassembler:
    """Buffers raw notification bytes and yields complete frames as they arrive.

    BLE notifications split a single TTLock frame across 20-byte chunks.
    The frame is length-prefixed, so the end is computed from the declared
    payload length: the payload is AES ciphertext and may legitimately
    contain the CRLF terminator, so scanning for CRLF would cut the frame
    mid-ciphertext. The terminator is still checked at the computed offset
    and used to resynchronise, since a header byte pair can also occur
    inside ciphertext.

    An early CRLF cannot be treated as evidence of a bad length — that is
    the legitimate case above — so a corrupt length byte makes the buffer
    wait for the bytes it declares. That wait is bounded: the length field
    is one byte, so no frame can claim more than 270 bytes in total.
    """

    __slots__ = ("_buf",)

    def __init__(self) -> None:
        """Start with an empty buffer."""
        self._buf = bytearray()

    def feed(self, chunk: bytes) -> list[Frame]:
        """Append `chunk` and return any frames that are now complete."""
        self._buf.extend(chunk)
        out: list[Frame] = []
        while True:
            start = self._buf.find(HEADER)
            if start < 0:
                # A header can straddle two notifications; keep the tail byte.
                del self._buf[: max(len(self._buf) - 1, 0)]
                break
            del self._buf[:start]
            if len(self._buf) >= 3 and self._buf[2] < MIN_PROTOCOL_TYPE:
                # Locks below protocol type 5 are rejected at the
                # advertisement layer, so this is a mis-sync, not a frame.
                del self._buf[: len(HEADER)]
                continue
            size = _declared_frame_len(bytes(self._buf))
            if size is None or len(self._buf) < size:
                break
            if bytes(self._buf[size - len(TRAILER) : size]) != TRAILER:
                # The declared length does not land on a terminator, so this
                # header was ciphertext rather than a frame start.
                del self._buf[: len(HEADER)]
                continue
            raw = bytes(self._buf[: size - len(TRAILER)])
            del self._buf[:size]
            try:
                out.append(Frame.parse(raw))
            except ValueError:
                continue
        return out
