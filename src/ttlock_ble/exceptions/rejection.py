"""Turns a lock's FAILED reply into the most specific `LockRejectedError`."""

from __future__ import annotations

from ..constants import LockErrorCode
from .credential_already_exists import CredentialAlreadyExistsError
from .credential_not_found import CredentialNotFoundError
from .lock_rejected import LockRejectedError
from .storage_full import StorageFullError

_ERROR_TYPES: dict[int, type[LockRejectedError]] = {
    LockErrorCode.LOCK_PASSWORD_EXIST: CredentialAlreadyExistsError,
    LockErrorCode.LOCK_PASSWORD_NOT_EXIST: CredentialNotFoundError,
    LockErrorCode.LOCK_NO_FREE_MEMORY: StorageFullError,
    LockErrorCode.IC_CARD_NOT_EXIST: CredentialNotFoundError,
    LockErrorCode.FR_NOT_EXIST: CredentialNotFoundError,
    LockErrorCode.RECORD_NOT_EXIST: CredentialNotFoundError,
    LockErrorCode.RECORD_ALREADY_EXIST: CredentialAlreadyExistsError,
}


def rejection_error(action: str, error_code: int | None) -> LockRejectedError:
    """Return the exception for a refused credential command.

    `DUPLICATE_DATA` (0x19) is deliberately left generic: device-property
    reads answer an unknown step with that same byte, so it does not
    reliably mean "already stored".
    """
    error_type = (
        _ERROR_TYPES.get(error_code, LockRejectedError)
        if error_code is not None
        else LockRejectedError
    )
    return error_type(action, error_code)
