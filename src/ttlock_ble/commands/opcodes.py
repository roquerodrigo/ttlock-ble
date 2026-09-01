"""Command opcodes carried in the V3 frame header.

Values mirror `com.ttlock.bl.sdk.command.Command` in the official Android
SDK for `lockType=5` (V3).
"""

from __future__ import annotations

CMD_SEARCH_DEVICE_FEATURE = 0x01
CMD_INIT_PASSWORDS = 0x31
CMD_CHECK_RANDOM = 0x30
CMD_TIME_CALIBRATE = 0x43
CMD_GET_LOCK_TIME = 0x34
CMD_CHECK_ADMIN = 0x41
CMD_CHECK_USER_TIME = 0x55
CMD_UNLOCK = 0x47
CMD_LOCK = 0x58
CMD_QUERY_STATE = 0x14
CMD_SWITCH = 0x68
CMD_GET_AES_KEY = 0x19
CMD_RESPONSE = 0x54
CMD_AUTO_LOCK_MANAGE = 0x36
CMD_MANAGE_KEYBOARD_PASSWORD = 0x03
CMD_GET_OPERATE_LOG = 0x25
CMD_SET_LOCK_SOUND = 0x62  # reverse-engineered from device traffic - not in the SDK dump
CMD_MANAGE_FINGERPRINT = 0x06  # reverse-engineered; only the list sub-op (0x06) is confirmed

APICMD_UNLOCK_BY_USER = 4
APICMD_LOCK_BY_USER = 14
APICMD_UNLOCK_BY_ADMIN = 3
APICMD_LOCK_BY_ADMIN = 13
