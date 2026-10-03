"""IC card (tag) listing - CMD 0x05, sub-op 0x01 (IC_SEARCH, the confirmed indexed query).

Reverse-engineered from device traffic. Only the list sub-op is confirmed;
this module deliberately does not model enroll/delete/edit-validity or any
other sub-op that may share CMD 0x05 - see `opcodes.CMD_MANAGE_IC_CARD`.
Read-only, like `fingerprint`: adding, deleting or editing a card is out
of scope here.

Critical limitation, worth repeating at the protocol layer because it is
easy to miss at the call site: this query has zero visibility into cyclic
(day-of-week/time-range) restrictions. CMD 0x70, the mechanism that would
carry that data, is not implemented anywhere in this library yet, for any
credential type. A card decoded here as permanent or timed may in
practice also be cyclically restricted - see `models.CardEntry`.
"""

from __future__ import annotations

from ..models import CardEntry
from .encoding import decode_date5
from .envelope import RESPONSE_SUCCESS, parse_response_status
from .fingerprint import END_DATE_SENTINEL, START_DATE_SENTINEL

_LIST_OPERATION = 0x01

# A SUCCESS response's data is [battery][op_echo][position:2][card_id][start:5][end:5].
# `card_id`'s length is not confirmed to be the same for every lock: the
# official SDK reads 8 bytes when its own id+dates buffer (position and
# everything after it, excluding battery and op_echo) is exactly 20 bytes,
# and 4 otherwise. Translated into this module's full `data` (battery and
# op_echo included), that SDK threshold lands on a *different* total
# length than 20 - the two lengths below, not the SDK's own literal 20.
_SHORT_ENTRY_DATA_LENGTH = 18  # 4-byte card_id - confirmed on real hardware
_LONG_ENTRY_DATA_LENGTH = 22  # 8-byte card_id - from the SDK, not independently confirmed
_SHORT_CARD_ID_LENGTH = 4
_LONG_CARD_ID_LENGTH = 8

# Dates use the same 5-byte decimal encoding and the same sentinels as
# fingerprints (re-exported above, not redefined) - see `commands.fingerprint`.

# End-of-list is a SUCCESS response whose data is [battery][op_echo][0xFF][0xFF]
# (captured on real hardware as the data `55 01 ff ff`), not a FAILED status -
# mirrors `commands.fingerprint`'s end-of-list shape exactly.
_END_OF_LIST_DATA_LENGTH = 4
_END_OF_LIST_TAIL = bytes([_LIST_OPERATION, 0xFF, 0xFF])


def payload_card_list(index: int) -> bytes:
    """Build the CMD 0x05 sub-op 0x01 payload for one indexed card query.

    `index` starts at 0 and increments by 1 per call - each call returns
    at most one enrolled card, or the end-of-list response. Mirrors
    `payload_fingerprint_list`'s indexing exactly.
    """
    return bytes([_LIST_OPERATION]) + index.to_bytes(2, "big")


def parse_card_list_response(plaintext: bytes) -> CardEntry | None:
    """Decode one CMD 0x05/0x01 response. Returns `None` at the end-of-list marker.

    Raises `RuntimeError` on a FAILED status. Raises `ValueError` if a
    SUCCESS response's data matches neither confirmed entry length.

    Wire layout of a SUCCESS response's data, confirmed on real hardware
    for the 4-byte `card_id` case:

        [0]        battery percentage - not exposed on `CardEntry`
        [1]        op_echo (always 0x01)
        [2:4]      position (index + 1) - discarded; not a total count,
                   mirrors `parse_fingerprint_list_response`'s `position`
                   exactly, including the same caution against reading
                   more into it than that
        [4:4+N]    card_id (N = 4 or 8 bytes, see the module docstring)
        [4+N:9+N]  start_date (5-byte decimal date)
        [9+N:14+N] end_date (5-byte decimal date)

    Unlike `FingerprintEntry`, there is no `slot` field here - the
    confirmed capture's byte count leaves no room for one between
    `card_id` and the dates.
    """
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS:
        raise RuntimeError(f"card list FAILED: status={status:#x} err={data.hex()}")
    if len(data) == _END_OF_LIST_DATA_LENGTH and data[1:] == _END_OF_LIST_TAIL:
        return None
    if len(data) == _LONG_ENTRY_DATA_LENGTH:
        card_id_length = _LONG_CARD_ID_LENGTH
    elif len(data) == _SHORT_ENTRY_DATA_LENGTH:
        card_id_length = _SHORT_CARD_ID_LENGTH
    else:
        raise ValueError(f"card list unexpected data length {len(data)}: {plaintext.hex()}")
    card_id_end = 4 + card_id_length
    start_date_raw = data[card_id_end : card_id_end + 5]
    end_date_raw = data[card_id_end + 5 : card_id_end + 10]
    return CardEntry(
        card_id=data[4:card_id_end],
        start_date=None if start_date_raw == START_DATE_SENTINEL else decode_date5(start_date_raw),
        end_date=None if end_date_raw == END_DATE_SENTINEL else decode_date5(end_date_raw),
    )
