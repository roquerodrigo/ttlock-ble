"""TTLockError: raised by the BLE client when the lock rejects or times out a command."""

from __future__ import annotations


class TTLockError(RuntimeError):
    """Raised by `TTLockClient` for any BLE-side or protocol-side failure."""
