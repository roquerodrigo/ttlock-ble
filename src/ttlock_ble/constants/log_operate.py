"""LogOperate: record-type tags emitted in COMM_GET_OPERATE_LOG entries."""

from __future__ import annotations

from enum import IntEnum


class LogOperate(IntEnum):
    """Operation log record types — mirror of `LogOperate.java` in the SDK.

    Names are kept close to the upstream Java constants (minus the
    `OPERATE_TYPE_` prefix where it added no information) so the cross-
    reference stays one-to-one. The parser dispatches on these values
    to decide how to interpret each record's variable-length payload;
    unknown bytes still surface as raw ints via the `record_type`
    field, so a missing entry here doesn't break decoding.
    """

    @classmethod
    def coerce(cls, value: int) -> LogOperate | int:
        """Lift a raw byte to the matching enum member, or pass through if unknown.

        Firmware revisions can emit record-type bytes we don't have a
        symbolic name for — callers should still receive the raw int
        rather than losing the data to a `ValueError`.
        """
        try:
            return cls(value)
        except ValueError:
            return value

    MOBILE_UNLOCK = 1
    SERVER_UNLOCK = 3
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
    CLEAR_IC_SUCCEED = 16
    IC_UNLOCK_SUCCEED = 17
    DELETE_IC_SUCCEED = 18
    BONG_UNLOCK = 19
    FR_UNLOCK_SUCCEED = 20
    ADD_FR = 21
    FR_UNLOCK_FAILED = 22
    DELETE_FR_SUCCEED = 23
    CLEAR_FR_SUCCEED = 24
    IC_UNLOCK_FAILED = 25
    OPERATE_BLE_LOCK = 26
    OPERATE_KEY_UNLOCK = 27
    GATEWAY_UNLOCK = 28
    ILLEGAL_UNLOCK = 29
    DOOR_SENSOR_LOCK = 30
    DOOR_SENSOR_UNLOCK = 31
    DOOR_GO_OUT = 32
    FR_LOCK = 33
    PASSCODE_LOCK = 34
    IC_LOCK = 35
    OPERATE_KEY_LOCK = 36
    REMOTE_CONTROL_KEY = 37
    PASSCODE_UNLOCK_FAILED_LOCK_REVERSE = 38
    IC_UNLOCK_FAILED_LOCK_REVERSE = 39
    FR_UNLOCK_FAILED_LOCK_REVERSE = 40
    APP_UNLOCK_FAILED_LOCK_REVERSE = 41
    APP_DEAD_LOCK = 52
    IC_UNLOCK_FAILED_BLACKLIST = 51
    WIRELESS_KEY_FOB = 55
    WIRELESS_KEY_PAD = 56
    QR_CODE_UNLOCK_SUCCESS = 57
    QR_CODE_UNLOCK_FAILED = 58
    FACE_3D_UNLOCK_SUCCESS = 67
    FACE_3D_UNLOCK_FAILED_LOCK_REVERSE = 68
    FACE_3D_LOCK = 69
    FACE_3D_ADD_SUCCESS = 70
    FACE_3D_UNLOCK_FAILED_INVALID_TIME = 71
    FACE_3D_DELETE_SUCCESS = 72
    FACE_3D_CLEAR_SUCCESS = 73
    CPU_CARD_UNLOCK_FAILED = 74
    APP_AUTH_KEY_UNLOCK_SUCCESS = 75
    GATEWAY_AUTH_KEY_UNLOCK_SUCCESS = 76
    DOUBLE_CHECK_KEY_UNLOCK = 77
    DOUBLE_CHECK_PASSCODE_UNLOCK = 78
    DOUBLE_CHECK_FINGER_PRINT_UNLOCK = 79
    DOUBLE_CHECK_CARD_UNLOCK = 80
    DOUBLE_CHECK_FACE_UNLOCK = 81
    DOUBLE_CHECK_KEY_FOB_UNLOCK = 82
    DOUBLE_CHECK_PALM_VEIN_UNLOCK = 83
    PALM_VEIN_UNLOCK_SUCCESS = 84
    PALM_VEIN_UNLOCK_FAILED_LOCK_REVERSE = 85
    PALM_VEIN_LOCK = 86
    PALM_VEIN_ADD_SUCCESS = 87
    PALM_VEIN_UNLOCK_FAILED = 88
    PALM_VEIN_DELETE_SUCCESS = 89
    PALM_VEIN_CLEAR_SUCCESS = 90
    CARD_UNLOCK_FAILED = 91
    ADMIN_CODE_UNLOCK = 92
    ADD_PASSCODE_SUCCESSFULLY = 93
    THIRD_DEVICE_UNLOCK_SUCCESS = 94
    THIRD_DEVICE_LOCK_SUCCESS = 95
    THIRD_DEVICE_UNLOCK_FAILED_LOCK_REVERSE = 96
    THIRD_DEVICE_UNLOCK_FAILED_INVALID_TIME = 97
    DOUBLE_CHECK_THIRD_DEVICE_VERIFY = 98
    ADD_THIRD_DEVICE = 99
    DELETE_THIRD_DEVICE = 100
    CLEAR_THIRD_DEVICE = 101
