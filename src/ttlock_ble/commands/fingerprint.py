"""Fingerprint management - CMD 0x06: add (sub-op 2), delete (3), clear (4), modify (5), list (6).

Reverse-engineered from device traffic. Enrolling, changing a fingerprint's
dates, deleting one fingerprint and clearing every fingerprint were captured
from the official app on an SN478_PV53 lock (firmware 6.4.43.240529); enrolling,
changing dates and deleting one were also captured on an SN484_PV53 lock
(firmware 6.5.15.240522). The listing was confirmed on real hardware.

A fingerprint cannot be added by number: the lock must read the finger, so
there is no counterpart of `commands.card.payload_card_add`.

Critical limitation, worth repeating at the protocol layer because it is
easy to miss at the call site: the listing has zero visibility into cyclic
(day-of-week/time-range) restrictions. A separate, confirmed opcode
(CMD 0x70) handles those, entirely independent of this mechanism. A
fingerprint decoded here as permanent or timed may in practice also be
cyclically restricted - see `models.FingerprintEntry`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..constants import FingerprintEnrollmentStep
from ..models import FingerprintEnrollmentProgress, FingerprintEntry, Permanent, SingleUse
from .encoding import decode_date5, encode_date5
from .envelope import RESPONSE_SUCCESS, parse_response_status

if TYPE_CHECKING:
    from ..models import Validity

_ADD_OPERATION = 0x02
_DELETE_OPERATION = 0x03
_CLEAR_OPERATION = 0x04
_MODIFY_OPERATION = 0x05
_LIST_OPERATION = 0x06
_ERROR_CREDENTIAL_NOT_FOUND = 0x1A
_ENTRY_DATA_LENGTH = 20
_FINGERPRINT_ID_LENGTH = 6

# Sub-op 2 with this operand puts the lock in add mode, waiting for a finger. Replies to
# it, after [battery][op echo]: the lock is ready, a touch was recorded, or the finger
# was enrolled.
_ENTER_ADD_MODE = 0x01
_FINGERPRINT_READ = 0x01
_ADD_MODE_READY = 0x02
_TOUCH_RECORDED = 0x03
_READY_DATA_LENGTH = 4
_TOUCH_DATA_LENGTH = 5
_READ_DATA_LENGTH = 3 + _FINGERPRINT_ID_LENGTH

START_DATE_SENTINEL = bytes([0x00, 0x01, 0x01, 0x00, 0x00])  # 2000-01-01 00:00, "never set"
END_DATE_SENTINEL = bytes([0x63, 0x01, 0x01, 0x00, 0x00])  # 2099-01-01 00:00, "permanent"

# End-of-list is a SUCCESS response whose data is [battery][op_echo][0xFF][0xFF]
# (captured on real hardware as the plaintext `06 01 64 06 ff ff`), not a FAILED
# status - only the tail after the battery byte is matched.
_END_OF_LIST_DATA_LENGTH = 4
_END_OF_LIST_TAIL = bytes([_LIST_OPERATION, 0xFF, 0xFF])


def validity_dates(validity: Validity, subject: str) -> bytes:
    """Return `[start 5B][end 5B]` for a validity; cards and fingerprints have no single-use form.

    `subject` names the credential in the `ValueError` for `SingleUse`.
    """
    if isinstance(validity, SingleUse):
        raise ValueError(f"a {subject} cannot be single-use")  # noqa: TRY004 -- ValueError is the contract for input the lock cannot take
    permanent = START_DATE_SENTINEL + END_DATE_SENTINEL
    if isinstance(validity, Permanent) or validity.start is None or validity.end is None:
        return permanent
    return encode_date5(validity.start) + encode_date5(validity.end)


def check_fingerprint_validity(validity: Validity) -> None:
    """Raise `ValueError` unless a fingerprint can have this validity, without connecting."""
    validity_dates(validity, "fingerprint")


def payload_fingerprint_enroll() -> bytes:
    """Build the CMD 0x06 sub-op 0x02 payload that puts the lock in add mode, waiting for a finger.

    Captured on SN478_PV53 and SN484_PV53; the current official app sends this
    directly. Never send a bare sub-op 4 first: that is `payload_fingerprint_clear`
    and removes every fingerprint.
    """
    return bytes([_ADD_OPERATION, _ENTER_ADD_MODE])


def parse_fingerprint_enrollment_reply(data: bytes) -> FingerprintEnrollmentProgress | bytes:
    """Decode one reply to the add-mode command: the progress so far, or the new fingerprint's id.

    `data` is a reply's data after the `[0x06][status]` envelope, starting
    with the battery byte. Captured on both models, which ask for 4 touches:

        [battery][02][02][N]            add mode ready, N touches required
        [battery][02][03][count][N]     touch `count` of N recorded
        [battery][02][01][id:6]         enrolled: 4-byte fingerprint id + 2-byte slot

    Returns `FingerprintEnrollmentProgress` for the first two and the 6-byte
    id for the last. Raises `ValueError` for anything else, without echoing it.
    """
    if len(data) >= _READY_DATA_LENGTH and data[1] == _ADD_OPERATION:
        kind = data[2]
        if kind == _ADD_MODE_READY and len(data) == _READY_DATA_LENGTH and data[3] > 0:
            return FingerprintEnrollmentProgress(
                FingerprintEnrollmentStep.WAITING_FOR_FINGER, 0, data[3]
            )
        if kind == _TOUCH_RECORDED and len(data) == _TOUCH_DATA_LENGTH and 0 < data[3] <= data[4]:
            return FingerprintEnrollmentProgress(
                FingerprintEnrollmentStep.TOUCH_RECORDED, data[3], data[4]
            )
        if kind == _FINGERPRINT_READ and len(data) == _READ_DATA_LENGTH:
            return data[3:]
    raise ValueError(f"fingerprint enrollment unexpected reply of {len(data)} bytes")


def payload_fingerprint_modify(fingerprint_id: bytes, validity: Validity) -> bytes:
    """Build the CMD 0x06 sub-op 0x05 payload that sets a fingerprint's dates.

    Layout `[05][id:6][start][end]`. Captured from the official app for dated
    fingerprints, after an enrollment and when editing one (SN478_PV53,
    SN484_PV53). `Permanent` and an unbounded `Weekly` send the dates the lock
    lists for a permanent fingerprint, 2000-01-01 00:00 and 2099-01-01 00:00;
    an SN478_PV53 lock accepted the finger afterwards. Windows of a `Weekly`
    validity are not part of this payload. Raises `ValueError` for `SingleUse`
    or an id that is not 6 bytes.
    """
    return (
        bytes([_MODIFY_OPERATION])
        + _checked(fingerprint_id)
        + validity_dates(validity, "fingerprint")
    )


def payload_fingerprint_delete(fingerprint_id: bytes) -> bytes:
    """Build the CMD 0x06 sub-op 0x03 payload that deletes one fingerprint: `[03][id:6]`."""
    return bytes([_DELETE_OPERATION]) + _checked(fingerprint_id)


def payload_fingerprint_clear() -> bytes:
    """Build the CMD 0x06 sub-op 0x04 payload that deletes every fingerprint on the lock: `[04]`."""
    return bytes([_CLEAR_OPERATION])


def _checked(fingerprint_id: bytes) -> bytes:
    if len(fingerprint_id) != _FINGERPRINT_ID_LENGTH:
        raise ValueError(f"fingerprint id must be {_FINGERPRINT_ID_LENGTH} bytes")
    return fingerprint_id


def payload_fingerprint_list(position: int) -> bytes:
    """Build the CMD 0x06 sub-op 0x06 payload for one fingerprint list query.

    `position` is a cursor, not an index: start at 0, then pass back the
    position the previous reply carried. The lock answers with the next
    enrolled fingerprint after that position - or the end-of-list response
    - so positions skip over deleted slots.
    """
    return bytes([_LIST_OPERATION]) + position.to_bytes(2, "big")


def parse_fingerprint_list_response(plaintext: bytes) -> FingerprintEntry | None:
    """Decode one CMD 0x06/0x06 response. Returns `None` at the end-of-list marker.

    Same as `parse_fingerprint_list_page`, minus the position.
    """
    page = parse_fingerprint_list_page(plaintext)
    return None if page is None else page[0]


def parse_fingerprint_list_page(plaintext: bytes) -> tuple[FingerprintEntry, int] | None:
    """Decode one CMD 0x06/0x06 response into `(entry, position)`.

    Returns `None` at the end-of-list marker. `position` is the cursor to
    send as the next request (see `payload_fingerprint_list`).

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
        [2:4]   position - the cursor for the next query; not an index
                and not a total count (it skips deleted slots)
        [4:8]   fingerprint_id
        [8:10]  slot
        [10:15] start_date (5-byte decimal date)
        [15:20] end_date (5-byte decimal date)
    """
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS:
        code = data[0] if data else None
        if code == _ERROR_CREDENTIAL_NOT_FOUND:
            raise RuntimeError(f"credential not found (0x1A): status={status:#x}")
        raise RuntimeError(f"fingerprint list FAILED: status={status:#x} data_length={len(data)}")
    if len(data) == _END_OF_LIST_DATA_LENGTH and data[1:] == _END_OF_LIST_TAIL:
        return None
    if len(data) < _ENTRY_DATA_LENGTH:
        raise ValueError(f"fingerprint list payload too short: {len(data)} bytes")
    start_date_raw = data[10:15]
    end_date_raw = data[15:20]
    entry = FingerprintEntry(
        fingerprint_id=data[4:8],
        slot=int.from_bytes(data[8:10], "big"),
        start_date=None if start_date_raw == START_DATE_SENTINEL else decode_date5(start_date_raw),
        end_date=None if end_date_raw == END_DATE_SENTINEL else decode_date5(end_date_raw),
    )
    return entry, int.from_bytes(data[2:4], "big")
