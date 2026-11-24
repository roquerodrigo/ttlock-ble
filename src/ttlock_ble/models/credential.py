"""Credential: one card or fingerprint, as the lock addresses it in credential commands."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..constants import CredentialType
from .card_entry import CardEntry

if TYPE_CHECKING:
    from .fingerprint_entry import FingerprintEntry

_FINGERPRINT_ID_LENGTH = 6
_CARD_ID_LENGTHS = (4, 8)
_SHORT_CARD_MAX = 0xFFFFFFFF
_LONG_CARD_MAX = 0xFFFFFFFFFFFFFFFF


@dataclass(frozen=True, slots=True)
class Credential:
    """A card (its number) or a fingerprint (its 6-byte id), as the lock addresses it.

    Build one with `card`, `fingerprint` or `of` rather than directly; the
    constructor only checks that `identifier` has a length the lock uses
    for `credential_type`. Two values are equal only when their bytes are,
    so a card listed with an 8-byte id equals `of(entry)`, not
    `card(number)`, which picks 4 bytes for any number that fits. The id
    never appears in `repr`: it is enough to clone a card.
    """

    credential_type: CredentialType
    identifier: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Reject an identifier whose length the lock does not use for `kind`."""
        kind = CredentialType(self.credential_type)
        object.__setattr__(self, "credential_type", kind)
        valid = (
            (_FINGERPRINT_ID_LENGTH,) if kind == CredentialType.FINGERPRINT else _CARD_ID_LENGTHS
        )
        if len(self.identifier) not in valid:
            lengths = " or ".join(map(str, valid))
            raise ValueError(
                f"{kind.name.lower()} id must be {lengths} bytes, got {len(self.identifier)}"
            )

    @classmethod
    def card(cls, number: int) -> Credential:
        """Address the card with this number: 4 bytes on the wire, 8 above 0xFFFFFFFF.

        For a card the lock lists with an 8-byte id, use `of(entry)` or
        build the value from those exact bytes instead.
        """
        if not 0 <= number <= _LONG_CARD_MAX:
            raise ValueError("card number must fit in 8 bytes")
        length = _CARD_ID_LENGTHS[0] if number <= _SHORT_CARD_MAX else _CARD_ID_LENGTHS[1]
        return cls(CredentialType.CARD, number.to_bytes(length, "big"))

    @classmethod
    def fingerprint(cls, identifier: bytes) -> Credential:
        """Address the fingerprint with this 6-byte id - see `FingerprintEntry.identifier`."""
        return cls(CredentialType.FINGERPRINT, bytes(identifier))

    @classmethod
    def of(cls, entry: CardEntry | FingerprintEntry) -> Credential:
        """Address a card or fingerprint as listed by the lock."""
        if isinstance(entry, CardEntry):
            return cls(CredentialType.CARD, entry.card_id)
        return cls.fingerprint(entry.identifier)

    @property
    def card_number(self) -> int | None:
        """The card's number, or `None` for a fingerprint."""
        if self.credential_type != CredentialType.CARD:
            return None
        return int.from_bytes(self.identifier, "big")
