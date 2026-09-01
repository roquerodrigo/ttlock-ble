"""Fingerprint enrollment listing - CMD 0x06, sub-op 0x06 (the confirmed indexed query).

Reverse-engineered from device traffic. Only the list sub-op is confirmed;
this module deliberately does not model enroll/delete/edit-validity or any
other sub-op that may share CMD 0x06 - see `opcodes.CMD_MANAGE_FINGERPRINT`.

Critical limitation, worth repeating at the protocol layer because it is
easy to miss at the call site: this query has zero visibility into cyclic
(day-of-week/time-range) restrictions. A separate, confirmed opcode
(CMD 0x70) handles those, entirely independent of this mechanism. A
fingerprint decoded here as permanent or timed may in practice also be
cyclically restricted - see `models.FingerprintEntry`.
"""

from __future__ import annotations

import datetime as dt

from ..models import FingerprintEntry
from .encoding import decode_date5
from .envelope import RESPONSE_SUCCESS, parse_response_status

_LIST_SUBOP = 0x06
_ERROR_CREDENTIAL_NOT_FOUND = 0x1A

START_DATE_SENTINEL = bytes(
    [0x00, 0x01, 0x01, 0x00, 0x00]
)  # 2000-01-01 00:00, "never explicitly set"
END_DATE_SENTINEL = bytes([0x63, 0x01, 0x01, 0x00, 0x00])  # 2099-01-01 00:00, "permanent"

# Decoded equivalents, for comparison when parsing responses - the one place
# that defines what a sentinel date decodes to, so a lock model that turns
# out to use a different sentinel only needs updating here.
START_DATE_SENTINEL_DT = dt.datetime(2000, 1, 1, 0, 0)  # noqa: DTZ001 -- lock RTC is naive
END_DATE_SENTINEL_DT = dt.datetime(2099, 1, 1, 0, 0)  # noqa: DTZ001 -- lock RTC is naive

# End-of-list is a SUCCESS response, not a special status - confirmed on
# real hardware (an empty enrollment) as the 6-byte plaintext
# `06 01 64 06 ff ff`: cmd_echo=0x06, status=0x01 (SUCCESS), then a
# 4-byte data of [battery=0x64][op_echo=0x06][0xFF][0xFF]. The battery
# byte's value isn't checked, only its presence and the 3-byte tail.
# The original spec for this response ("[0x06][0xFF][0xFF]") turned out
# to be shorthand that dropped the status and battery bytes - a literal
# 3-byte match against that never fires, so every query (including a
# genuinely empty list) fell through to "payload too short" instead of
# returning cleanly. This is what real-device testing caught.
_END_OF_LIST_DATA_LEN = 4
_END_OF_LIST_TAIL = bytes([_LIST_SUBOP, 0xFF, 0xFF])


def payload_fingerprint_list(index: int) -> bytes:
    """Build the CMD 0x06 sub-op 0x06 payload for one indexed fingerprint query.

    `index` starts at 0 and increments by 1 per call - each call returns
    at most one enrolled fingerprint, or the end-of-list response.
    """
    return bytes([_LIST_SUBOP]) + index.to_bytes(2, "big")


def parse_fingerprint_list_response(plaintext: bytes) -> FingerprintEntry | None:
    """Decode one CMD 0x06/0x06 response. Returns `None` at the end-of-list marker.

    Raises `RuntimeError` on a FAILED status, matching
    `parse_check_user_time_response`; a confirmed 0x1A error code
    ("credential ID/slot not found") is called out explicitly in the
    message rather than left as an opaque hex byte. Raises `ValueError`
    if a SUCCESS response is shorter than the confirmed 20-byte entry
    shape.

    Wire layout of a SUCCESS response's data (20 bytes) - the leading
    battery byte was confirmed the same way the end-of-list one was:
    real-device output showed `position` (index + 1, meant to be
    discarded) leaking verbatim into `fp_id`'s first byte across 7
    consecutive entries, the unmistakable signature of every field below
    being read one byte too early:

        [0]     battery percentage - not exposed; see the class this
                data assembles into, `models.FingerprintEntry`
        [1]     op_echo (always 0x06)
        [2:4]   position (index + 1) - discarded; not a total count,
                confirmed wrong in this role during the investigation
        [4:8]   fp_id
        [8:10]  slot
        [10:15] start_date (5-byte decimal date)
        [15:20] end_date (5-byte decimal date)
    """
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS:
        code = data[0] if data else None
        if code == _ERROR_CREDENTIAL_NOT_FOUND:
            raise RuntimeError(f"credential not found (0x1A): status={status:#x} err={data.hex()}")
        raise RuntimeError(f"fingerprint list FAILED: status={status:#x} err={data.hex()}")
    if len(data) == _END_OF_LIST_DATA_LEN and data[1:] == _END_OF_LIST_TAIL:
        return None
    if len(data) < 20:
        raise ValueError(f"fingerprint list payload too short: {plaintext.hex()}")
    fp_id = data[4:8]
    slot = int.from_bytes(data[8:10], "big")
    start_date = decode_date5(data[10:15])
    end_date = decode_date5(data[15:20])
    if start_date == START_DATE_SENTINEL_DT:
        start_date = None
    if end_date == END_DATE_SENTINEL_DT:
        end_date = None
    return FingerprintEntry(fp_id=fp_id, slot=slot, start_date=start_date, end_date=end_date)
