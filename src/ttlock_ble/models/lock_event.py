"""LockEvent: structured wrapper for an unsolicited BLE notification from the lock."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LockEvent:
    """A push notification emitted by the lock outside any command exchange.

    These arrive when the door is operated by means other than the SDK
    issuing a command — keypad code, fingerprint, IC card, mechanical key,
    or the official mobile app while we happen to be connected.

    Fields:
        cmd_echo:   the opcode the lock claims this event corresponds to
                    (e.g. 0x47 for an unlock-style operation).
        status:     `1` for SUCCESS, `0` for FAILED — same envelope as
                    command responses (see `parse_response_status`).
        data:       remaining decrypted payload bytes; layout depends on
                    `cmd_echo` and is firmware-specific. Consumers (e.g.
                    Home Assistant integrations) typically forward these
                    raw bytes as an event attribute.
    """

    cmd_echo: int
    status: int
    data: bytes
