"""LogEntry: one row from the lock's on-device operation log."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LogEntry:
    """A single entry from `COMM_GET_OPERATE_LOG`.

    Fields populated depend on `record_type` (the firmware encodes
    different payloads per operation):

    - `uid` is set for app/BLE/gateway unlocks.
    - `password` carries: keypad code (string of digits), IC card
      number, fingerprint id, or fob MAC — depending on record type.
    - `key_id` identifies an accessory (key fob, wireless keypad).
    - `accessory_battery` is the wireless accessory's battery, when
      relevant; the lock's own battery is in `lock_battery`.
    - `delete_date` only set for the "all passwords cleared" record.
    """

    record_number: int
    record_type: int
    operate_date: str
    lock_battery: int
    uid: int | None = None
    record_id: int | None = None
    password: str | None = None
    new_password: str | None = None
    delete_date: str | None = None
    key_id: int | None = None
    accessory_battery: int | None = None
