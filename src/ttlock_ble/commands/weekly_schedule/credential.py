"""Credential type and credential-id helpers for the weekly-schedule command (CMD 0x70)."""

from __future__ import annotations

from ...constants import CredentialType
from ...models import Credential

_FINGERPRINT_ID_LENGTH = 4
_SLOT_MAX = 0xFFFF

__all__ = [
    "CredentialType",
    "card_credential_id",
    "fingerprint_credential_id",
    "validate_credential",
]


def fingerprint_credential_id(fingerprint_id: bytes, slot: int) -> bytes:
    """Encode a fingerprint as its 6-byte credential id: 4-byte fingerprint id + 2-byte slot.

    Raises `ValueError` if `fingerprint_id` is not exactly 4 bytes or `slot`
    does not fit in 2 bytes.
    """
    if len(fingerprint_id) != _FINGERPRINT_ID_LENGTH:
        raise ValueError(
            f"fingerprint_id must be {_FINGERPRINT_ID_LENGTH} bytes: length={len(fingerprint_id)}"
        )
    if not 0 <= slot <= _SLOT_MAX:
        raise ValueError(f"slot must fit in 2 bytes (0..{_SLOT_MAX})")
    return bytes(fingerprint_id) + slot.to_bytes(2, "big")


def card_credential_id(card_number: int) -> bytes:
    """Encode a card number as its credential id: 4 bytes, or 8 above 0xFFFFFFFF.

    The 8-byte form follows the SDK and was not tested on hardware.
    Raises `ValueError` for a negative number or one that needs more than 8 bytes.
    """
    try:
        return Credential.card(card_number).identifier
    except ValueError:
        raise ValueError("card_number must fit in 8 bytes") from None


def validate_credential(credential_type: int, credential_id: bytes) -> None:
    """Check that `credential_id` has a length valid for `credential_type`.

    Raises `ValueError` for an unknown type or a wrong id length.
    """
    try:
        kind = CredentialType(credential_type)
    except ValueError:
        raise ValueError(f"unknown credential_type: {credential_type}") from None
    try:
        Credential(kind, credential_id)
    except ValueError as error:
        raise ValueError(f"credential_id rejected: {error}") from None
