"""UnsupportedFeatureError: the lock does not advertise what a command needs."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .ttlock import TTLockError

if TYPE_CHECKING:
    from ..constants import LockFeature


class UnsupportedFeatureError(TTLockError):
    """Raised before sending a command whose feature bit the lock's own mask leaves unset."""

    def __init__(self, action: str, feature: LockFeature) -> None:
        """Name the refused `action` and the missing `feature` in the message."""
        self.action = action
        self.feature = feature
        super().__init__(f"Failed to {action}: lock does not support {feature.name}")

    def __reduce__(self) -> tuple[type[UnsupportedFeatureError], tuple[str, LockFeature]]:
        """Rebuild from the constructor arguments, so the error survives pickling and copying."""
        return type(self), (self.action, self.feature)
