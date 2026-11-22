"""Credential type and credential-id helpers for the weekly-schedule command (CMD 0x70)."""

from __future__ import annotations

from enum import IntEnum

_FINGERPRINT_ID_LENGTH = 4
_SLOT_MAX = 0xFFFF
_CARD_SHORT_MAX = 0xFFFFFFFF
_CARD_LONG_MAX = 0xFFFFFFFFFFFFFFFF
_CARD_SHORT_LENGTH = 4
_CARD_LONG_LENGTH = 8

FINGERPRINT_CREDENTIAL_ID_LENGTH = 6
CARD_CREDENTIAL_ID_LENGTHS = (_CARD_SHORT_LENGTH, _CARD_LONG_LENGTH)


class CredentialType(IntEnum):
    """Credential type byte of the weekly-schedule command."""

    FINGERPRINT = 1
    CARD = 2


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
        raise ValueError(f"slot must be 0..{_SLOT_MAX}: {slot}")
    return bytes(fingerprint_id) + slot.to_bytes(2, "big")


def card_credential_id(card_number: int) -> bytes:
    """Encode a card number as its credential id: 4 bytes, or 8 above 0xFFFFFFFF.

    The 8-byte form follows the SDK and was not tested on hardware.
    Raises `ValueError` for a negative number or one that needs more than 8 bytes.
    """
    if not 0 <= card_number <= _CARD_LONG_MAX:
        raise ValueError(f"card_number must be 0..{_CARD_LONG_MAX}: {card_number}")
    length = _CARD_SHORT_LENGTH if card_number <= _CARD_SHORT_MAX else _CARD_LONG_LENGTH
    return card_number.to_bytes(length, "big")


def validate_credential(credential_type: int, credential_id: bytes) -> None:
    """Check that `credential_id` has a length valid for `credential_type`.

    Raises `ValueError` for an unknown type or a wrong id length.
    """
    if credential_type == CredentialType.FINGERPRINT:
        valid_lengths: tuple[int, ...] = (FINGERPRINT_CREDENTIAL_ID_LENGTH,)
    elif credential_type == CredentialType.CARD:
        valid_lengths = CARD_CREDENTIAL_ID_LENGTHS
    else:
        raise ValueError(f"unknown credential_type: {credential_type}")
    if len(credential_id) not in valid_lengths:
        raise ValueError(
            f"credential_id for type {credential_type} must be one of {valid_lengths} bytes: "
            f"length={len(credential_id)}"
        )
