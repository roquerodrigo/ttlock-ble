"""Weekly (cyclic) schedule codec for fingerprints and cards - CMD 0x70.

Pure encode/decode functions, payload builders for QUERY, CLEAR and ADD,
reply parsers, a sans-IO schedule read and a pure write plan. Self-contained
on purpose: it imports neither the client nor the transport;
`credentials.WeeklyScheduleManager` drives it. Confirmed on SN484_PV53
(firmware 6.5.15.240522) and SN534-4P-T78-BELL_PV53 (firmware 6.5.20).

Conclusions only here; the evidence is in roquerodrigo/ttlock-ble#119.
Non-weekly record kinds, the month byte, REMOVE (operation 3), operation 5 and
passcode schedules are out of scope.
"""

from __future__ import annotations

from .credential import CredentialType, card_credential_id, fingerprint_credential_id
from .payloads import (
    payload_weekly_schedule_add,
    payload_weekly_schedule_clear,
    payload_weekly_schedule_query,
)
from .plan import plan_weekly_schedule_write
from .query_reply import WeeklyScheduleQueryReply, parse_weekly_schedule_query_reply
from .reader import MAX_RECORDS, read_weekly_schedule
from .record import WEEKLY_KIND, WeeklyScheduleRecord, decode_record, encode_record
from .write_reply import (
    WeeklyScheduleWriteReply,
    parse_weekly_schedule_add_reply,
    parse_weekly_schedule_clear_reply,
)

__all__ = [
    "MAX_RECORDS",
    "WEEKLY_KIND",
    "CredentialType",
    "WeeklyScheduleQueryReply",
    "WeeklyScheduleRecord",
    "WeeklyScheduleWriteReply",
    "card_credential_id",
    "decode_record",
    "encode_record",
    "fingerprint_credential_id",
    "parse_weekly_schedule_add_reply",
    "parse_weekly_schedule_clear_reply",
    "parse_weekly_schedule_query_reply",
    "payload_weekly_schedule_add",
    "payload_weekly_schedule_clear",
    "payload_weekly_schedule_query",
    "plan_weekly_schedule_write",
    "read_weekly_schedule",
]
