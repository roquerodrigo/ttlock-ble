"""Public exception hierarchy for ttlock_ble."""

from __future__ import annotations

from .card_already_enrolled import CardAlreadyEnrolledError
from .card_presented_late import CardPresentedLateError
from .cloud import CloudError
from .credential_already_exists import CredentialAlreadyExistsError
from .credential_not_found import CredentialNotFoundError
from .enrollment_timeout import EnrollmentTimeoutError
from .lock_rejected import LockRejectedError
from .rejection import rejection_error
from .reply_timeout import ReplyTimeoutError
from .storage_full import StorageFullError
from .ttlock import TTLockError
from .unsupported_feature import UnsupportedFeatureError

__all__ = [
    "CardAlreadyEnrolledError",
    "CardPresentedLateError",
    "CloudError",
    "CredentialAlreadyExistsError",
    "CredentialNotFoundError",
    "EnrollmentTimeoutError",
    "LockRejectedError",
    "ReplyTimeoutError",
    "StorageFullError",
    "TTLockError",
    "UnsupportedFeatureError",
    "rejection_error",
]
