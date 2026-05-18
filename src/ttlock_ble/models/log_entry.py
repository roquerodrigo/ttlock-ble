"""LogEntry: one row from the lock's on-device operation log."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import datetime as dt

    from ..constants import LogOperate


@dataclass(frozen=True, slots=True)
class LogEntry:
    """A single entry from `COMM_GET_OPERATE_LOG`.

    Fields populated depend on `record_type` (the firmware encodes
    different payloads per operation):

    - `uid`/`record_id` are set for app, BLE, and gateway unlock/lock
      records (record types 1, 26, 28, 37, 41, 52, 75, 76, 77).
    - `password` carries: keypad code (digits), IC card number,
      fingerprint id, palm-vein id, QR seq, or fob MAC — depending on
      record type.
    - `new_password` is set only for the keyboard-modify variants.
    - `key_id` identifies an accessory (key fob, wireless keypad,
      remote-control key).
    - `accessory_battery` is the wireless accessory's battery, when
      relevant; the lock's own battery is always in `lock_battery`.
    - `delete_date` is set for the "all passwords cleared" record.
    - `start_date`/`end_date` are set for the "passcode added"
      record (type 93), expressing the validity window (no seconds —
      the firmware encodes those entries with a 5-byte date).

    Date fields are naive `datetime`s in lock-local time (the lock's RTC
    has no timezone — see `TTLockClient.calibrate_time`). They are
    `None` only when the firmware sent bytes that don't form a valid
    calendar date, which the parser tolerates rather than raising.
    """

    record_number: int
    record_type: LogOperate | int
    operate_date: dt.datetime | None
    lock_battery: int
    uid: int | None = None
    record_id: int | None = None
    password: str | None = None
    new_password: str | None = None
    delete_date: dt.datetime | None = None
    key_id: int | None = None
    accessory_battery: int | None = None
    start_date: dt.datetime | None = None
    end_date: dt.datetime | None = None
