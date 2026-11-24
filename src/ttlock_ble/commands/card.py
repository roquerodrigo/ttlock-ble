"""IC card management - CMD 0x05: list (sub-op 1), add (2), delete (3), clear (4), modify (5).

Reverse-engineered from device traffic. Listing, enrolling by tap, deleting
one card, clearing every card and changing a card's dates were captured
from the official app on an SN484_PV53 lock (firmware 6.5.15.240522).
Adding a card by its number is SDK-only (the app does not offer it) and was
confirmed on the same lock by running this SDK.

The listing has zero visibility into weekly (day-of-week/time-range)
windows, which CMD 0x70 carries - see `models.CardEntry` and
`credentials.WeeklyScheduleManager`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..models import CardEntry, Permanent, SingleUse
from .encoding import decode_date5, encode_date5
from .envelope import RESPONSE_SUCCESS, parse_response_status
from .fingerprint import END_DATE_SENTINEL, START_DATE_SENTINEL

if TYPE_CHECKING:
    from ..models import Validity

_LIST_OPERATION = 0x01
_ADD_OPERATION = 0x02
_DELETE_OPERATION = 0x03
_CLEAR_OPERATION = 0x04
_MODIFY_OPERATION = 0x05

# Sub-op 2 with this operand puts the lock in add mode, waiting for a card.
_ENTER_ADD_MODE = 0x01
# Replies to it, after [battery][op echo]: the lock is waiting, or a card was read.
_WAITING_FOR_CARD = 0x02
_CARD_READ = 0x01
_ENROLL_WAITING_DATA_LENGTH = 3

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
        raise RuntimeError(f"card list FAILED: status={status:#x} data_length={len(data)}")
    if len(data) == _END_OF_LIST_DATA_LENGTH and data[1:] == _END_OF_LIST_TAIL:
        return None
    if len(data) == _LONG_ENTRY_DATA_LENGTH:
        card_id_length = _LONG_CARD_ID_LENGTH
    elif len(data) == _SHORT_ENTRY_DATA_LENGTH:
        card_id_length = _SHORT_CARD_ID_LENGTH
    else:
        raise ValueError(f"card list unexpected data length {len(data)}")
    card_id_end = 4 + card_id_length
    start_date_raw = data[card_id_end : card_id_end + 5]
    end_date_raw = data[card_id_end + 5 : card_id_end + 10]
    return CardEntry(
        card_id=data[4:card_id_end],
        start_date=None if start_date_raw == START_DATE_SENTINEL else decode_date5(start_date_raw),
        end_date=None if end_date_raw == END_DATE_SENTINEL else decode_date5(end_date_raw),
    )


def payload_card_enroll() -> bytes:
    """Build the CMD 0x05 sub-op 0x02 payload that puts the lock in add mode, waiting for a tap."""
    return bytes([_ADD_OPERATION, _ENTER_ADD_MODE])


def parse_card_enrollment_reply(data: bytes) -> bytes | None:
    """Decode one reply to the add-mode command: `None` while waiting, else the card's id.

    `data` is a reply's data after the `[0x05][status]` envelope:
    `[battery][02][02]` says the lock waits for a card, and
    `[battery][02][01][card id]` is pushed when one is presented (captured
    with a 4-byte id; an 8-byte one is accepted too, from the SDK, not
    tested). Raises `ValueError` for anything else, without echoing it.
    """
    if len(data) >= _ENROLL_WAITING_DATA_LENGTH and data[1] == _ADD_OPERATION:
        if len(data) == _ENROLL_WAITING_DATA_LENGTH and data[2] == _WAITING_FOR_CARD:
            return None
        card_id = data[3:]
        if data[2] == _CARD_READ and len(card_id) in (_SHORT_CARD_ID_LENGTH, _LONG_CARD_ID_LENGTH):
            return card_id
    raise ValueError(f"card enrollment unexpected reply of {len(data)} bytes")


def _dates(validity: Validity) -> bytes:
    """Return `[start 5B][end 5B]` for a validity; cards have no single-use form."""
    if isinstance(validity, SingleUse):
        raise ValueError("a card cannot be single-use")  # noqa: TRY004 -- ValueError is the contract for input the lock cannot take
    permanent = START_DATE_SENTINEL + END_DATE_SENTINEL
    if isinstance(validity, Permanent) or validity.start is None or validity.end is None:
        return permanent
    return encode_date5(validity.start) + encode_date5(validity.end)


def check_card_validity(validity: Validity) -> None:
    """Raise `ValueError` unless a card can have this validity, without connecting."""
    _dates(validity)


def payload_card_add(card_id: bytes, validity: Validity) -> bytes:
    """Build the CMD 0x05 sub-op 0x02 payload that adds a card by its id: `[02][id][start][end]`.

    Not captured (the app does not add by number); confirmed on an
    SN484_PV53 lock for a permanent card with a 4-byte id. `Permanent` and an
    unbounded `Weekly` send the dates the lock lists for a permanent card,
    2000-01-01 00:00 and 2099-01-01 00:00;
    the SDK's own default for a card without dates is about 2000-02-01 and
    2099-12-01. A `Weekly` validity's windows are not part of this payload.
    Raises `ValueError` for `SingleUse`.
    """
    return bytes([_ADD_OPERATION]) + card_id + _dates(validity)


def payload_card_modify(card_id: bytes, validity: Validity) -> bytes:
    """Build the CMD 0x05 sub-op 0x05 payload that sets a card's dates: `[05][id][start][end]`.

    Captured from the official app for dated cards. For `Permanent` and an
    unbounded `Weekly` it sends the dates the lock lists for a permanent
    card; an SN484_PV53 lock then lists the card as permanent and accepts it.
    Windows of a `Weekly` validity are not part of this payload. Raises
    `ValueError` for `SingleUse`.
    """
    return bytes([_MODIFY_OPERATION]) + card_id + _dates(validity)


def payload_card_delete(card_id: bytes) -> bytes:
    """Build the CMD 0x05 sub-op 0x03 payload that deletes one card: `[03][id]`."""
    return bytes([_DELETE_OPERATION]) + card_id


def payload_card_clear() -> bytes:
    """Build the CMD 0x05 sub-op 0x04 payload that deletes every card on the lock: `[04]`."""
    return bytes([_CLEAR_OPERATION])
