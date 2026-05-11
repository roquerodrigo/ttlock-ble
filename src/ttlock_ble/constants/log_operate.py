"""LogOperate: record-type tags emitted in COMM_GET_OPERATE_LOG entries."""

from __future__ import annotations

from enum import IntEnum


class LogOperate(IntEnum):
    """Operation log record types (subset of `LogOperate.java`).

    Only the values we've seen on a DLock-XP V3 lock are enumerated.
    The parser falls back to the raw integer when a record carries a
    value not listed here, so unknown operation types still surface.
    """

    MOBILE_UNLOCK = 1
    KEYBOARD_PASSWORD_UNLOCK = 4
    KEYBOARD_MODIFY_PASSWORD = 5
    KEYBOARD_REMOVE_SINGLE_PASSWORD = 6
    ERROR_PASSWORD_UNLOCK = 7
    KEYBOARD_REMOVE_ALL_PASSWORDS = 8
    KEYBOARD_PASSWORD_KICKED = 9
    USE_DELETE_CODE = 10
    PASSCODE_EXPIRED = 11
    SPACE_INSUFFICIENT = 12
    PASSCODE_IN_BLACK_LIST = 13
    DOOR_REBOOT = 14
    ADD_IC = 15
    CLEAR_IC = 16
    IC_UNLOCK_SUCCEED = 17
    DELETE_IC_SUCCEED = 18
    BONG_UNLOCK = 19
    FR_UNLOCK_SUCCEED = 20
    ADD_FR = 21
    FR_UNLOCK_FAILED = 22
    DELETE_FR_SUCCEED = 23
    BLE_LOCK = 33
    PASSCODE_LOCK = 34
    IC_LOCK = 35
    FR_LOCK = 36
    GATEWAY_UNLOCK = 45
    REMOTE_CONTROL_KEY = 47
    APP_UNLOCK_FAILED_LOCK_REVERSE = 50
    PASSCODE_UNLOCK_FAILED_LOCK_REVERSE = 52
    IC_UNLOCK_FAILED_LOCK_REVERSE = 54
    FR_UNLOCK_FAILED_LOCK_REVERSE = 55
    WIRELESS_KEY_FOB = 57
    WIRELESS_KEY_PAD = 58
