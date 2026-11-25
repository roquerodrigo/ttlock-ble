"""FingerprintEnrolledLateError: a finger completed enrollment after the caller's timeout."""

from __future__ import annotations

from .ttlock import TTLockError


class FingerprintEnrolledLateError(TTLockError):
    """Raised when a finger completes enrollment after the caller's timeout.

    The lock keeps add mode open while touches continue, so it enrolled that
    finger as permanent and unrestricted; the SDK deletes the new entry at
    once (SN478_PV53). `removed` says whether that worked - when it did not,
    the finger may still open the lock.
    """

    def __init__(self, message: str, *, removed: bool) -> None:
        """Keep whether the late fingerprint was deleted again next to the message."""
        super().__init__(message)
        self.removed = removed

    def __reduce__(self) -> tuple[object, ...]:
        """Rebuild from the message and `removed`, so the error survives pickling and copying."""
        return _rebuild, (str(self), self.removed)


def _rebuild(message: str, removed: bool) -> FingerprintEnrolledLateError:  # noqa: FBT001 -- pickle passes it positionally
    return FingerprintEnrolledLateError(message, removed=removed)
