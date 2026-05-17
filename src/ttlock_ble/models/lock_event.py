"""LockEvent: structured wrapper for an unsolicited BLE notification from the lock."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..constants import LockState

_COMM_SEARCH_BICYCLE_STATUS = 0x14
_STATE_PUSH_LEN = 3
_LOG_PUSH_LEN = 15


@dataclass(frozen=True, slots=True)
class LockEvent:
    """A push notification emitted by the lock outside any command exchange.

    These arrive when the door is operated by means other than the SDK
    issuing a command — keypad code, fingerprint, IC card, mechanical key,
    or the official mobile app while we happen to be connected.

    Fields populated depend on `cmd_echo` and the payload layout the
    firmware chose. The raw bytes always live in `data` so callers can
    fall back to manual parsing for opcodes / variants this SDK doesn't
    yet recognise.

    For `cmd_echo == 0x14` (the lock's `SEARCH_BICYCLE_STATUS` heartbeat
    repurposed as a push channel) we recognise two shapes seen on the
    DLock-XP V3:

    - 3-byte payload `[battery, state, flag]` — terse state heartbeat.
    - 15-byte payload `[battery, uid(4 BE), record_id(4 BE), date(6)]`
      — log entry written. `date` is six little-endian decimal-encoded
      bytes (`YYMMDDhhmmss`), same convention as `parse_operate_log_response`.
    """

    cmd_echo: int
    status: int
    data: bytes
    battery: int | None = None
    lock_state: LockState | None = None
    uid: int | None = None
    record_id: int | None = None
    timestamp: str | None = None

    @classmethod
    def from_payload(cls, cmd_echo: int, status: int, data: bytes) -> LockEvent:
        """Build a `LockEvent` and decode the known cmd_echo=0x14 variants.

        Unrecognised opcodes or payload lengths still get a `LockEvent`
        with the raw `data`; the optional decoded fields stay `None`.
        """
        from ..constants import LockState

        raw = bytes(data)
        if cmd_echo != _COMM_SEARCH_BICYCLE_STATUS or len(raw) == 0:
            return cls(cmd_echo=cmd_echo, status=status, data=raw)
        battery = raw[0]
        if len(raw) == _STATE_PUSH_LEN:
            try:
                state = LockState(raw[1])
            except ValueError:
                state = None
            return cls(
                cmd_echo=cmd_echo,
                status=status,
                data=raw,
                battery=battery,
                lock_state=state,
            )
        if len(raw) >= _LOG_PUSH_LEN:
            uid = int.from_bytes(raw[1:5], "big")
            record_id = int.from_bytes(raw[5:9], "big")
            timestamp = _decode_timestamp(raw[9:15])
            return cls(
                cmd_echo=cmd_echo,
                status=status,
                data=raw,
                battery=battery,
                uid=uid,
                record_id=record_id,
                timestamp=timestamp,
            )
        return cls(cmd_echo=cmd_echo, status=status, data=raw, battery=battery)


def _decode_timestamp(date_bytes: bytes) -> str | None:
    """Decode the lock's 6-byte decimal-encoded `YYMMDDhhmmss` into ISO-8601.

    Each byte holds a decimal value (e.g. 0x1a = 26 for the year 2026,
    not 0x1a hex characters). Returns `None` if any byte is out of the
    plausible range — a guard against misinterpreting a payload that
    happens to be 15 bytes but isn't actually a log push.
    """
    try:
        yy, mm, dd, hh, mn, ss = date_bytes
    except ValueError:
        return None
    if not (
        0 <= yy <= 99
        and 1 <= mm <= 12
        and 1 <= dd <= 31
        and 0 <= hh <= 23
        and 0 <= mn <= 59
        and 0 <= ss <= 59
    ):
        return None
    return f"20{yy:02d}-{mm:02d}-{dd:02d} {hh:02d}:{mn:02d}:{ss:02d}"
