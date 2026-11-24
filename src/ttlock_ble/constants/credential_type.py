"""CredentialType: which kind of credential a weekly-schedule command addresses."""

from __future__ import annotations

from enum import IntEnum


class CredentialType(IntEnum):
    """Credential type byte of the weekly-schedule command (CMD 0x70)."""

    FINGERPRINT = 1
    CARD = 2
