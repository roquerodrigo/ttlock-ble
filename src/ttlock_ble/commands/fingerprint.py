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

from ..models import FingerprintEntry
from .encoding import decode_date5
from .envelope import RESPONSE_SUCCESS, parse_response_status

_LIST_OPERATION = 0x06
_ERROR_CREDENTIAL_NOT_FOUND = 0x1A
_ENTRY_DATA_LENGTH = 20

START_DATE_SENTINEL = bytes([0x00, 0x01, 0x01, 0x00, 0x00])  # 2000-01-01 00:00, "never set"
END_DATE_SENTINEL = bytes([0x63, 0x01, 0x01, 0x00, 0x00])  # 2099-01-01 00:00, "permanent"

# End-of-list is a SUCCESS response whose data is [battery][op_echo][0xFF][0xFF]
# (captured on real hardware as the plaintext `06 01 64 06 ff ff`), not a FAILED
# status - only the tail after the battery byte is matched.
_END_OF_LIST_DATA_LENGTH = 4
_END_OF_LIST_TAIL = bytes([_LIST_OPERATION, 0xFF, 0xFF])


def payload_fingerprint_list(index: int) -> bytes:
    """Build the CMD 0x06 sub-op 0x06 payload for one indexed fingerprint query.

    `index` starts at 0 and increments by 1 per call - each call returns
    at most one enrolled fingerprint, or the end-of-list response.
    """
    return bytes([_LIST_OPERATION]) + index.to_bytes(2, "big")


def parse_fingerprint_list_response(plaintext: bytes) -> FingerprintEntry | None:
    """Decode one CMD 0x06/0x06 response. Returns `None` at the end-of-list marker.

    Raises `RuntimeError` on a FAILED status, matching
    `parse_check_user_time_response`; a confirmed 0x1A error code
    ("credential ID/slot not found") is called out explicitly in the
    message rather than left as an opaque hex byte. Raises `ValueError`
    if a SUCCESS response is shorter than the confirmed 20-byte entry
    shape.

    Wire layout of a SUCCESS response's data (20 bytes), confirmed on
    real hardware - reading it without the leading battery byte shifts
    every field one position and leaks `position` into `fingerprint_id`:

        [0]     battery percentage - not exposed on `FingerprintEntry`
        [1]     op_echo (always 0x06)
        [2:4]   position (index + 1) - discarded; not a total count
        [4:8]   fingerprint_id
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
    if len(data) == _END_OF_LIST_DATA_LENGTH and data[1:] == _END_OF_LIST_TAIL:
        return None
    if len(data) < _ENTRY_DATA_LENGTH:
        raise ValueError(f"fingerprint list payload too short: {plaintext.hex()}")
    start_date_raw = data[10:15]
    end_date_raw = data[15:20]
    return FingerprintEntry(
        fingerprint_id=data[4:8],
        slot=int.from_bytes(data[8:10], "big"),
        start_date=None if start_date_raw == START_DATE_SENTINEL else decode_date5(start_date_raw),
        end_date=None if end_date_raw == END_DATE_SENTINEL else decode_date5(end_date_raw),
    )
