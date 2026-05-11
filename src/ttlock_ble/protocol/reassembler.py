"""FrameReassembler: buffer BLE notifications until a CRLF-terminated frame is complete."""

from __future__ import annotations

from .constants import HEADER, TRAILER
from .frame import Frame


class FrameReassembler:
    """Buffers raw notification bytes and yields complete frames as they arrive.

    BLE notifications often split a single TTLock frame across multiple
    20-byte chunks. This reassembler scans for the CRLF terminator and
    parses everything from the most recent HEADER up to (but excluding)
    the trailer as one frame. Anything before the HEADER is dropped as
    resync noise.
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
            buf = bytes(self._buf)
            tidx = buf.find(TRAILER)
            if tidx < 0:
                break
            hidx = buf.rfind(HEADER, 0, tidx)
            if hidx < 0:
                del self._buf[: tidx + len(TRAILER)]
                continue
            raw = buf[hidx:tidx]
            del self._buf[: tidx + len(TRAILER)]
            try:
                out.append(Frame.parse(raw))
            except ValueError:
                continue
        return out
