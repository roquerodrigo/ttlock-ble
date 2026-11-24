"""CardAlreadyEnrolledError: the card was already on the lock."""

from __future__ import annotations

from .credential_already_exists import CredentialAlreadyExistsError


class CardAlreadyEnrolledError(CredentialAlreadyExistsError):
    """Raised when `enroll` meets a card the lock already holds, or `add` is asked for one.

    A lock resets a card that is tapped again in add mode: its dates become
    permanent and its weekly windows are wiped (SN484_PV53; the official app
    does not detect this). `CardManager.enroll` therefore writes the previous
    dates and windows back, and `restored` says whether that worked - when it
    did not, the card may now be permanent and unrestricted. `restored` is
    `None` when nothing was changed on the lock, as when `add` refuses a card
    that is held.
    """

    def __init__(self, action: str, message: str, *, restored: bool | None = None) -> None:
        """Keep `message` as the whole text and `restored` next to it."""
        super().__init__(action, None, message)
        self.restored = restored
        self.args = (message,)

    def __str__(self) -> str:
        """Return the message alone, without the lock-rejection preamble."""
        return str(self.detail)

    def __reduce__(self) -> tuple[object, ...]:  # type: ignore[override]  # `restored` needs its own rebuild
        """Rebuild from the constructor arguments, so the error survives pickling and copying."""
        return _rebuild, (self.action, str(self.detail), self.restored)


def _rebuild(action: str, message: str, restored: bool | None) -> CardAlreadyEnrolledError:  # noqa: FBT001 -- pickle passes it positionally
    return CardAlreadyEnrolledError(action, message, restored=restored)
