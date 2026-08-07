"""TTLock V3 command opcodes and per-command payload builders / response parsers.

Maps directly to `com.ttlock.bl.sdk.command.Command` and its helpers in the
official Android SDK. We focus on `lockType=5` (V3), which covers virtually
every current DLock-XP / TTLock smart-lock SKU.

One submodule per command family — `session` for the handshake, `control`
for the bolt, `clock`, `auto_lock`, `passcode` and `operate_log` for the
rest — over the shared `opcodes`, `envelope` and `encoding` primitives.
"""

from __future__ import annotations

from .auto_lock import parse_auto_lock_response, payload_auto_lock_search, payload_auto_lock_set
from .clock import parse_get_lock_time_response, payload_get_lock_time, payload_time_calibrate
from .control import (
    LOCKED,
    UNLOCKED,
    parse_lock_status,
    parse_state_battery,
    payload_query_state,
    payload_unlock,
)
from .envelope import RESPONSE_FAILED, RESPONSE_SUCCESS, parse_response_status
from .opcodes import (
    APICMD_LOCK_BY_ADMIN,
    APICMD_LOCK_BY_USER,
    APICMD_UNLOCK_BY_ADMIN,
    APICMD_UNLOCK_BY_USER,
    CMD_AUTO_LOCK_MANAGE,
    CMD_CHECK_ADMIN,
    CMD_CHECK_RANDOM,
    CMD_CHECK_USER_TIME,
    CMD_GET_AES_KEY,
    CMD_GET_LOCK_TIME,
    CMD_GET_OPERATE_LOG,
    CMD_INIT_PASSWORDS,
    CMD_LOCK,
    CMD_MANAGE_KEYBOARD_PASSWORD,
    CMD_QUERY_STATE,
    CMD_RESPONSE,
    CMD_SEARCH_DEVICE_FEATURE,
    CMD_SWITCH,
    CMD_TIME_CALIBRATE,
    CMD_UNLOCK,
)
from .operate_log import parse_operate_log_response, payload_operate_log_request
from .passcode import payload_passcode_add, payload_passcode_clear, payload_passcode_delete
from .session import (
    VENDOR,
    parse_check_user_time_response,
    payload_check_admin,
    payload_check_random,
    payload_check_user_time,
    payload_get_aes_key,
)

__all__ = [
    "APICMD_LOCK_BY_ADMIN",
    "APICMD_LOCK_BY_USER",
    "APICMD_UNLOCK_BY_ADMIN",
    "APICMD_UNLOCK_BY_USER",
    "CMD_AUTO_LOCK_MANAGE",
    "CMD_CHECK_ADMIN",
    "CMD_CHECK_RANDOM",
    "CMD_CHECK_USER_TIME",
    "CMD_GET_AES_KEY",
    "CMD_GET_LOCK_TIME",
    "CMD_GET_OPERATE_LOG",
    "CMD_INIT_PASSWORDS",
    "CMD_LOCK",
    "CMD_MANAGE_KEYBOARD_PASSWORD",
    "CMD_QUERY_STATE",
    "CMD_RESPONSE",
    "CMD_SEARCH_DEVICE_FEATURE",
    "CMD_SWITCH",
    "CMD_TIME_CALIBRATE",
    "CMD_UNLOCK",
    "LOCKED",
    "RESPONSE_FAILED",
    "RESPONSE_SUCCESS",
    "UNLOCKED",
    "VENDOR",
    "parse_auto_lock_response",
    "parse_check_user_time_response",
    "parse_get_lock_time_response",
    "parse_lock_status",
    "parse_operate_log_response",
    "parse_response_status",
    "parse_state_battery",
    "payload_auto_lock_search",
    "payload_auto_lock_set",
    "payload_check_admin",
    "payload_check_random",
    "payload_check_user_time",
    "payload_get_aes_key",
    "payload_get_lock_time",
    "payload_operate_log_request",
    "payload_passcode_add",
    "payload_passcode_clear",
    "payload_passcode_delete",
    "payload_query_state",
    "payload_time_calibrate",
    "payload_unlock",
]
