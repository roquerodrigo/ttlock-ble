"""Payload builders for the weekly-schedule command (CMD 0x70): QUERY, CLEAR and ADD only.

No builder takes an operation parameter: operations 3 and 5 must not be
buildable through this API (see `operations`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .credential import validate_credential
from .operations import ADD_OPERATION, CLEAR_OPERATION, QUERY_OPERATION
from .record import encode_record

if TYPE_CHECKING:
    from .credential import CredentialType
    from .record import WeeklyScheduleRecord

_QUERY_PAYLOAD_LENGTH = 20
_CURSOR_MAX = 0xFFFF
_ADD_TRAILER = bytes(4)


def _credential_header(
    operation: int, credential_type: CredentialType, credential_id: bytes
) -> bytes:
    validate_credential(credential_type, credential_id)
    return bytes([operation, int(credential_type), len(credential_id)]) + credential_id


def payload_weekly_schedule_query(
    credential_type: CredentialType, credential_id: bytes, cursor: int | None = None
) -> bytes:
    """Build the QUERY payload, zero-padded to 20 bytes as in every hardware test.

    `cursor` is the position of the last record read (the reply to a query
    without cursor gives the first record). Because of the padding, `None`
    and `0` give identical bytes. A 1-byte cursor is not offered: it
    returned the first record again, reason not tested.
    """
    if cursor is not None and not 0 <= cursor <= _CURSOR_MAX:
        raise ValueError(f"cursor must be 0..{_CURSOR_MAX}: {cursor}")
    body = _credential_header(QUERY_OPERATION, credential_type, credential_id)
    body += (cursor or 0).to_bytes(2, "big")
    return body.ljust(_QUERY_PAYLOAD_LENGTH, b"\x00")


def payload_weekly_schedule_clear(credential_type: CredentialType, credential_id: bytes) -> bytes:
    """Build the CLEAR payload, which removes all weekly records of the credential (no padding)."""
    return _credential_header(CLEAR_OPERATION, credential_type, credential_id)


def payload_weekly_schedule_add(
    credential_type: CredentialType, credential_id: bytes, record: WeeklyScheduleRecord
) -> bytes:
    """Build the ADD payload for one record, with the four trailing zero bytes.

    The SDK writes the trailer as zeros and carries no data in it; sending
    without it was not tested, so it is always sent.
    """
    header = _credential_header(ADD_OPERATION, credential_type, credential_id)
    return header + encode_record(record) + _ADD_TRAILER
