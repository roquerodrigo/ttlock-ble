"""CardPresentedLateError: a card was tapped after the enrollment timeout."""

from __future__ import annotations

from .ttlock import TTLockError


class CardPresentedLateError(TTLockError):
    """Raised when a card arrives after the caller's timeout but before the lock left add mode.

    The lock enrolled that card as permanent and unrestricted; the SDK deletes
    it at once. `removed` says whether that worked - when it did not, the card
    may still open the lock.
    """

    def __init__(self, message: str, *, removed: bool) -> None:
        """Keep whether the late card was deleted again next to the message."""
        super().__init__(message)
        self.removed = removed

    def __reduce__(self) -> tuple[object, ...]:
        """Rebuild from the message and `removed`, so the error survives pickling and copying."""
        return _rebuild, (str(self), self.removed)


def _rebuild(message: str, removed: bool) -> CardPresentedLateError:  # noqa: FBT001 -- pickle passes it positionally
    return CardPresentedLateError(message, removed=removed)
