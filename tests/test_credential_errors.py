"""A lock's refusal turns into the most specific exception."""

from __future__ import annotations

import copy
import pickle

import pytest

from ttlock_ble import (
    CredentialAlreadyExistsError,
    CredentialNotFoundError,
    LockErrorCode,
    LockFeature,
    LockRejectedError,
    StorageFullError,
    TTLockError,
    UnsupportedFeatureError,
)
from ttlock_ble.exceptions import rejection_error


@pytest.mark.parametrize(
    ("error_code", "error_type"),
    [
        (0x14, CredentialAlreadyExistsError),
        (0x15, CredentialNotFoundError),
        (0x16, StorageFullError),
        (0x18, CredentialNotFoundError),
        (0x19, LockRejectedError),
        (0x1A, CredentialNotFoundError),
        (0x1F, CredentialNotFoundError),
        (0x27, CredentialAlreadyExistsError),
    ],
)
def test_error_code_maps_to_its_exception(
    error_code: int, error_type: type[LockRejectedError]
) -> None:
    error = rejection_error("delete_card", error_code)
    assert type(error) is error_type
    assert isinstance(error, TTLockError)
    assert error.error_code == error_code
    assert error.action == "delete_card"


def test_message_names_a_known_error_code() -> None:
    error = rejection_error("add_passcode", LockErrorCode.LOCK_PASSWORD_EXIST)
    assert str(error) == (
        "Failed to add_passcode: lock rejected the command with error 0x14 (LOCK_PASSWORD_EXIST)"
    )


def test_message_keeps_an_unknown_error_code_as_hex() -> None:
    error = rejection_error("add_card", 0xEE)
    assert type(error) is LockRejectedError
    assert str(error) == "Failed to add_card: lock rejected the command with error 0xee"


def test_refusal_without_an_error_code() -> None:
    error = rejection_error("add_card", None)
    assert type(error) is LockRejectedError
    assert error.error_code is None
    assert str(error) == "Failed to add_card: lock rejected the command without an error code"


def test_unsupported_feature_names_the_bit() -> None:
    error = UnsupportedFeatureError("modify_passcode", LockFeature.MODIFY_PASSCODE_FUNCTION)
    assert isinstance(error, TTLockError)
    assert error.feature is LockFeature.MODIFY_PASSCODE_FUNCTION
    assert str(error) == "Failed to modify_passcode: lock does not support MODIFY_PASSCODE_FUNCTION"


@pytest.mark.parametrize(
    "error",
    [
        rejection_error("add_card", 0x16),
        rejection_error("add_card", None),
        CredentialNotFoundError("set_weekly_schedule", 0x16, "the lock may not hold it"),
        UnsupportedFeatureError("add_card", LockFeature.IC),
    ],
)
def test_errors_survive_pickling_and_copying(error: TTLockError) -> None:
    for clone in (pickle.loads(pickle.dumps(error)), copy.copy(error)):  # noqa: S301 -- round trip of our own object
        assert type(clone) is type(error)
        assert str(clone) == str(error)
        assert vars(clone) == vars(error)


def test_detail_is_appended_to_the_message() -> None:
    error = CredentialNotFoundError("set_weekly_schedule", 0x16, "the lock may not hold it")
    assert str(error) == (
        "Failed to set_weekly_schedule: lock rejected the command with error 0x16 "
        "(LOCK_NO_FREE_MEMORY); the lock may not hold it"
    )
