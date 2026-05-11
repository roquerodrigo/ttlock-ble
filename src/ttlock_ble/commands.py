"""TTLock V3 command opcodes and per-command payload builders / response parsers.

Maps directly to `com.ttlock.bl.sdk.command.Command` and its helpers in the
official Android SDK. We focus on `lockType=5` (V3), which covers virtually
every current DLock-XP / TTLock smart-lock SKU.
"""

from __future__ import annotations

import datetime as dt

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

APICMD_UNLOCK_BY_USER = 4
APICMD_LOCK_BY_USER = 14
APICMD_UNLOCK_BY_ADMIN = 3
APICMD_LOCK_BY_ADMIN = 13

VENDOR = "0658d44e0c504619a09c5b91be75a3a8"

RESPONSE_SUCCESS = 0x01
RESPONSE_FAILED = 0x00

LOCKED = 0
UNLOCKED = 1


def _int_to_bytes_be(value: int, n: int = 4) -> bytes:
    return value.to_bytes(n, "big", signed=False)


def _bcd_time10(time_str: str) -> bytes:
    """Pack a 10-digit `yyMMddHHmm` string into 5 BCD bytes (two digits per byte)."""
    if len(time_str) % 2:
        time_str = "0" + time_str
    out = bytearray()
    for i in range(0, len(time_str), 2):
        hi = int(time_str[i])
        lo = int(time_str[i + 1])
        out.append(((hi << 4) | lo) & 0xFF)
    return bytes(out)


def _decimal_time_bytes(time_str: str) -> bytes:
    """Pack a digit string into one byte per pair, decimal-encoded.

    Mirrors `dateTimeToBuffer` in ttlock-sdk-js: `parseInt(substr(2))` per
    pair, so "26" becomes byte 26 (0x1A), NOT 0x26 like BCD would. Used by
    COMM_TIME_CALIBRATE where the lock parses the bytes into a real
    `Calendar` (so 0x1A → year 2026, 0x26 → year 2038).
    """
    if len(time_str) % 2:
        time_str = "0" + time_str
    return bytes(int(time_str[i : i + 2]) for i in range(0, len(time_str), 2))


def payload_get_aes_key() -> bytes:
    """COMM_GET_AES_KEY data — vendor token, AES-encrypted with the session key."""
    return VENDOR.encode("ascii")


def payload_check_random(ps_from_lock: int, unlock_key: str | int) -> bytes:
    """COMM_CHECK_RANDOM — 4-byte BE of `(psFromLock + unlockKey) mod 2**32`."""
    sum_val = (int(ps_from_lock) + int(unlock_key)) & 0xFFFFFFFF
    return sum_val.to_bytes(4, "big")


def payload_check_user_time(
    uid: int = 0,
    start_date: str = "0001311400",
    end_date: str = "9911301400",
    lock_flag_pos: int = 0,
) -> bytes:
    """COMM_CHECK_USER_TIME — 17 bytes proving the key is valid right now.

    Wire layout matches `CheckUserTimeCommand.build()` in ttlock-sdk-js:

        [0:5]    start date BCD (yyMMddHHmm)
        [5:9]    end date BCD (first 4 bytes)
        [9]      end date BCD (last byte) — overlaps lockFlagPos high byte
        [10:13]  lockFlagPos (low 3 bytes, big-endian)
        [13:17]  uid (4 bytes, big-endian)

    Defaults match `TTLock.unlock()`: uid=0, lockFlagPos=0, plus the magic
    "permanent key" date strings the official client uses.
    """
    out = bytearray(17)
    out[0:5] = _bcd_time10(start_date)
    out[9] = (lock_flag_pos >> 24) & 0xFF
    out[10] = (lock_flag_pos >> 16) & 0xFF
    out[11] = (lock_flag_pos >> 8) & 0xFF
    out[12] = lock_flag_pos & 0xFF
    out[5:10] = _bcd_time10(end_date)
    out[13:17] = _int_to_bytes_be(uid, 4)
    return bytes(out)


def payload_check_admin(uid: int, admin_ps: str, lock_flag_pos: int) -> bytes:
    """COMM_CHECK_ADMIN — 11 bytes proving we know the admin password.

    Wire layout:

        [0:4]   admin password (4-byte BE int)
        [4:7]   lockFlagPos (3 bytes, big-endian)
        [7:11]  uid (4-byte BE int)
    """
    out = bytearray(11)
    out[0:4] = _int_to_bytes_be(int(admin_ps), 4)
    out[4] = (lock_flag_pos >> 16) & 0xFF
    out[5] = (lock_flag_pos >> 8) & 0xFF
    out[6] = lock_flag_pos & 0xFF
    out[7:11] = _int_to_bytes_be(uid, 4)
    return bytes(out)


def payload_unlock(ps_from_lock: int, unlock_key: str | int, ts_ms: int = 0) -> bytes:
    """COMM_UNLOCK / COMM_FUNCTION_LOCK — 8-byte authenticated control payload.

    Wire layout:

        [0:4]  (psFromLock + unlockKey) as UInt32 BE  (overflow wraps mod 2**32)
        [4:8]  current unix epoch seconds, BE

    `psFromLock` is a 4-byte token returned in the CHECK_USER_TIME response.
    Adding it to our numeric `unlockKey` proves both that the time-window
    check just passed AND that we know the per-key secret.
    """
    if ts_ms <= 0:
        ts_ms = int(dt.datetime.now(dt.UTC).timestamp() * 1000)
    sum_val = (int(ps_from_lock) + int(unlock_key)) & 0xFFFFFFFF
    out = bytearray(8)
    out[0:4] = sum_val.to_bytes(4, "big")
    out[4:8] = _int_to_bytes_be(ts_ms // 1000, 4)
    return bytes(out)


def payload_query_state() -> bytes:
    """COMM_SEARCH_BICYCLE_STATUS — fixed `SCIENER` ASCII literal (7 bytes)."""
    return b"SCIENER"


def payload_time_calibrate(when: dt.datetime | None = None) -> bytes:
    """COMM_TIME_CALIBRATE — 6 bytes `[YY, MM, DD, HH, mm, ss]` decimal-encoded.

    Each byte is the literal decimal value (year 2026 → byte 26 = 0x1A),
    NOT BCD. The lock keeps an RTC that drifts and needs periodic
    recalibration; HA integrations typically call this on connect and
    once a day thereafter.
    """
    moment = when or dt.datetime.now(dt.UTC)
    return _decimal_time_bytes(moment.strftime("%y%m%d%H%M%S"))


def parse_response_status(plaintext: bytes) -> tuple[int, int, bytes]:
    """Decode the universal `[cmd_echo][status][data...]` response wrapper.

    Returns `(cmd_echo, status, data)`. `status == RESPONSE_SUCCESS (1)`
    means OK; `RESPONSE_FAILED (0)` carries an error code in `data[0]`.
    """
    if len(plaintext) < 2:
        raise ValueError(f"response too short: {plaintext.hex()}")
    return plaintext[0], plaintext[1], plaintext[2:]


def parse_check_user_time_response(plaintext: bytes) -> int:
    """Extract `psFromLock` (UInt32 BE) from the CHECK_USER_TIME response.

    Wire layout: `[cmd_echo=0x55][status=0x01][psFromLock 4 BE][...]`.
    Raises if status != SUCCESS so callers can't accidentally proceed
    with a garbage value.
    """
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS:
        raise RuntimeError(f"checkUserTime FAILED: status={status:#x} err={data.hex()}")
    if len(data) < 4:
        raise ValueError(f"checkUserTime payload too short: {plaintext.hex()}")
    return int.from_bytes(data[:4], "big")


def parse_lock_status(plaintext: bytes) -> int:
    """Decode COMM_SEARCH_BICYCLE_STATUS lockState byte.

    Wire layout: `[cmd_echo][status][battery][lockState][...]`.
    Returns 0 (LOCKED), 1 (UNLOCKED), or -1 (UNKNOWN).
    """
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS or len(data) < 2:
        return -1
    return data[1]


def parse_state_battery(plaintext: bytes) -> int | None:
    """Battery percentage from a COMM_SEARCH_BICYCLE_STATUS response (byte 0)."""
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS or len(data) < 1:
        return None
    return data[0]


def payload_auto_lock_search() -> bytes:
    """Query the lock's current auto-lock delay (single op-type byte = SEARCH=0x01)."""
    from .constants import AutoLockOperate

    return bytes([AutoLockOperate.SEARCH])


def payload_auto_lock_set(seconds: int) -> bytes:
    """Set the auto-lock delay to `seconds` (3 bytes: op-type + UInt16 BE).

    `seconds=0` disables auto-lock; otherwise must fit in a UInt16 (max ~18h).
    """
    from .constants import AutoLockOperate

    if not 0 <= seconds <= 0xFFFF:
        raise ValueError(f"auto-lock seconds out of range [0, 65535]: {seconds}")
    return bytes([AutoLockOperate.MODIFY, (seconds >> 8) & 0xFF, seconds & 0xFF])


def parse_auto_lock_response(plaintext: bytes) -> tuple[int, int | None]:
    """Decode a COMM_AUTO_LOCK_MANAGE response.

    Returns `(seconds, battery_pct)`. `seconds=-1` means UNKNOWN (firmware
    didn't include a value, e.g. on MODIFY ack). `battery_pct=None` means
    the response didn't carry a battery byte.

    Wire layout (after the universal envelope):

        [0]    battery percentage
        [1]    op type echo (1=SEARCH, 2=MODIFY)
        [2:4]  current value (only on SEARCH)
        [4:6]  min allowed (optional)
        [6:8]  max allowed (optional)
    """
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS or len(data) < 2:
        return -1, None
    battery = data[0]
    op_type = data[1]
    seconds = int.from_bytes(data[2:4], "big") if op_type == 1 and len(data) >= 4 else -1
    return seconds, battery


def _check_passcode(code: str) -> None:
    if not (4 <= len(code) <= 9) or not code.isdigit():
        raise ValueError(f"keyboard passcode must be 4-9 digits, got {code!r}")


def _date5(date_str: str) -> bytes:
    """Pack `YYMMDDHHmm` into 5 decimal-encoded bytes (parseInt per pair)."""
    return _decimal_time_bytes(date_str)


def payload_passcode_add(
    pwd_type: int,
    code: str,
    start_date: str = "0001311400",
    end_date: str = "9912311400",
) -> bytes:
    """COMM_MANAGE_KEYBOARD_PASSWORD with op=ADD (2).

    Wire layout: `[op=2][type][len(code)][code chars][start 5B][end 5B?]`.
    Permanent passcodes carry both 5-byte windows; non-permanent ones omit
    the trailing end-date block (mirrors `ManageKeyboardPasswordCommand.buildAdd`).
    """
    from .constants import KeyboardPwdType, PwdOperateType

    _check_passcode(code)
    out = bytearray()
    out.append(PwdOperateType.ADD)
    out.append(pwd_type)
    out.append(len(code))
    out.extend(code.encode("ascii"))
    out.extend(_date5(start_date))
    if pwd_type != KeyboardPwdType.PERMANENT:
        out.extend(_date5(end_date))
    return bytes(out)


def payload_passcode_delete(pwd_type: int, code: str) -> bytes:
    """COMM_MANAGE_KEYBOARD_PASSWORD with op=REMOVE_ONE (3)."""
    from .constants import PwdOperateType

    _check_passcode(code)
    out = bytearray()
    out.append(PwdOperateType.REMOVE_ONE)
    out.append(pwd_type)
    out.append(len(code))
    out.extend(code.encode("ascii"))
    return bytes(out)


def payload_passcode_clear() -> bytes:
    """COMM_MANAGE_KEYBOARD_PASSWORD with op=CLEAR (1) — wipes all keypad codes."""
    from .constants import PwdOperateType

    return bytes([PwdOperateType.CLEAR])


def payload_operate_log_request(sequence: int = 0xFFFF) -> bytes:
    """COMM_GET_OPERATE_LOG request — sequence number as UInt16 BE.

    `sequence=0xFFFF` (default) asks the lock for "all newer entries you
    have"; when paginating, pass the largest `record_number` seen + 1.
    """
    return sequence.to_bytes(2, "big")


def parse_operate_log_response(plaintext: bytes) -> tuple[list[object], int]:
    """Decode COMM_GET_OPERATE_LOG into `(entries, last_sequence)`.

    Returns the list of `LogEntry`-shaped tuples and the last sequence
    number observed (caller passes this back via `payload_operate_log_request`
    to fetch the next page). Returns an empty list when the lock has no
    new entries.

    The actual `LogEntry` dataclass lives in `ttlock_ble.models`; this
    function is structured to keep `commands.py` free of imports from
    higher layers, so it returns `list[object]` of `LogEntry` instances.
    """
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS or len(data) < 2:
        return [], 0
    total_len = int.from_bytes(data[:2], "big")
    if total_len == 0:
        return [], 0
    sequence = int.from_bytes(data[2:4], "big")
    entries: list[object] = []
    idx = 4
    while idx < len(data):
        rec_len = data[idx]
        idx += 1
        rec_start = idx
        if rec_start + rec_len > len(data):
            break
        record_type = data[idx]
        idx += 1
        operate_date = "20" + "".join(f"{data[idx + i]:02d}" for i in range(6))
        idx += 6
        battery = data[idx]
        idx += 1
        entry = _decode_log_record(
            record_type=record_type,
            operate_date=operate_date,
            battery=battery,
            sequence=sequence - len(entries) - 1,
            data=data,
            idx=idx,
            rec_end=rec_start + rec_len,
        )
        entries.append(entry)
        idx = rec_start + rec_len
    return entries, sequence


def _decode_log_record(  # noqa: PLR0913, PLR0912  -- record-type dispatch is a flat switch
    record_type: int,
    operate_date: str,
    battery: int,
    sequence: int,
    data: bytes,
    idx: int,
    rec_end: int,
) -> object:
    """Build a `LogEntry` from one record body.

    Most variants we see on a DLock-XP V3 carry one of three payloads:
    `(uid, recordId)` for app/BLE/gateway unlocks, `(passcode_len, chars)`
    for keypad operations, or a 6-byte fixed accessory id for IC/FR/key fob.
    """
    from .constants import LogOperate
    from .models import LogEntry

    uid: int | None = None
    record_id: int | None = None
    password: str | None = None
    new_password: str | None = None
    delete_date: str | None = None
    key_id: int | None = None
    accessory_battery: int | None = None
    app_unlock_types = {
        LogOperate.MOBILE_UNLOCK.value,
        LogOperate.BLE_LOCK.value,
        LogOperate.GATEWAY_UNLOCK.value,
        LogOperate.APP_UNLOCK_FAILED_LOCK_REVERSE.value,
        LogOperate.REMOTE_CONTROL_KEY.value,
    }
    keypad_pair_types = {
        LogOperate.KEYBOARD_PASSWORD_UNLOCK.value,
        LogOperate.USE_DELETE_CODE.value,
        LogOperate.PASSCODE_EXPIRED.value,
        LogOperate.SPACE_INSUFFICIENT.value,
        LogOperate.PASSCODE_IN_BLACK_LIST.value,
        LogOperate.PASSCODE_LOCK.value,
        LogOperate.PASSCODE_UNLOCK_FAILED_LOCK_REVERSE.value,
        LogOperate.KEYBOARD_MODIFY_PASSWORD.value,
        LogOperate.KEYBOARD_REMOVE_SINGLE_PASSWORD.value,
        LogOperate.KEYBOARD_PASSWORD_KICKED.value,
    }
    if record_type in app_unlock_types and rec_end - idx >= 8:
        uid = int.from_bytes(data[idx : idx + 4], "big")
        record_id = int.from_bytes(data[idx + 4 : idx + 8], "big")
        if record_type == LogOperate.REMOTE_CONTROL_KEY.value and rec_end - idx >= 9:
            key_id = data[idx + 8]
    elif record_type in keypad_pair_types and idx < rec_end:
        pwd_len = data[idx]
        idx += 1
        password = data[idx : idx + pwd_len].decode("ascii", errors="replace")
        idx += pwd_len
        if idx < rec_end:
            new_pwd_len = data[idx]
            idx += 1
            new_password = data[idx : idx + new_pwd_len].decode("ascii", errors="replace")
    elif record_type == LogOperate.ERROR_PASSWORD_UNLOCK.value and idx < rec_end:
        pwd_len = data[idx]
        idx += 1
        password = data[idx : idx + pwd_len].decode("ascii", errors="replace")
    elif record_type == LogOperate.KEYBOARD_REMOVE_ALL_PASSWORDS.value and rec_end - idx >= 5:
        delete_date = "20" + "".join(f"{data[idx + i]:02d}" for i in range(5))
    elif record_type in {
        LogOperate.ADD_IC.value,
        LogOperate.DELETE_IC_SUCCEED.value,
        LogOperate.IC_UNLOCK_SUCCEED.value,
        LogOperate.IC_LOCK.value,
        LogOperate.IC_UNLOCK_FAILED_LOCK_REVERSE.value,
    }:
        # IC card id: 4 or 8 bytes depending on firmware revision.
        remaining = rec_end - idx
        if remaining >= 8:
            password = str(int.from_bytes(data[idx : idx + 8], "big"))
        elif remaining >= 4:
            password = str(int.from_bytes(data[idx : idx + 4], "big"))
    elif (
        record_type
        in {
            LogOperate.FR_UNLOCK_SUCCEED.value,
            LogOperate.ADD_FR.value,
            LogOperate.FR_UNLOCK_FAILED.value,
            LogOperate.DELETE_FR_SUCCEED.value,
            LogOperate.FR_LOCK.value,
            LogOperate.FR_UNLOCK_FAILED_LOCK_REVERSE.value,
        }
        and rec_end - idx >= 6
    ):
        # Fingerprint id: 6-byte big-endian integer (mirrors the JS reference,
        # which prepends two zero bytes and reads it as a signed 64-bit value).
        password = str(int.from_bytes(data[idx : idx + 6], "big"))
    elif (
        record_type
        in {
            LogOperate.BONG_UNLOCK.value,
            LogOperate.WIRELESS_KEY_FOB.value,
            LogOperate.WIRELESS_KEY_PAD.value,
        }
        and rec_end - idx >= 6
    ):
        # 6-byte MAC, transmitted little-endian; render as `aa:bb:cc:dd:ee:ff`.
        mac = data[idx : idx + 6]
        password = ":".join(f"{b:02x}" for b in reversed(mac))
        if record_type in {LogOperate.WIRELESS_KEY_FOB.value, LogOperate.WIRELESS_KEY_PAD.value}:
            if rec_end - idx >= 7:
                key_id = data[idx + 6]
            if rec_end - idx >= 8:
                accessory_battery = data[idx + 7]
    return LogEntry(
        record_number=sequence,
        record_type=record_type,
        operate_date=operate_date,
        lock_battery=battery,
        uid=uid,
        record_id=record_id,
        password=password,
        new_password=new_password,
        delete_date=delete_date,
        key_id=key_id,
        accessory_battery=accessory_battery,
    )
