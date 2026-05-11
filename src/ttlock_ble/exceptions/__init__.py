"""Public exception hierarchy for ttlock_ble."""

from __future__ import annotations

from .cloud import CloudError
from .ttlock import TTLockError

__all__ = ["CloudError", "TTLockError"]
