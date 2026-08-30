"""IntEnum families for the protocol's fixed option sets.

Most mirror the Java SDK's own constant groups; `LockVolume` is the
exception - reverse-engineered from BLE traffic rather than SDK source,
so its names come from the official app's UI instead (see its own
docstring). Re-exported so consumers can `import ttlock_ble.constants as
c` and use the symbols directly in UI / event mapping code.
"""

from __future__ import annotations

from .auto_lock_operate import AutoLockOperate
from .keyboard_pwd_type import KeyboardPwdType
from .lock_state import LockState
from .lock_volume import LockVolume
from .log_operate import LogOperate
from .pwd_operate_type import PwdOperateType
from .response_status import ResponseStatus

__all__ = [
    "AutoLockOperate",
    "KeyboardPwdType",
    "LockState",
    "LockVolume",
    "LogOperate",
    "PwdOperateType",
    "ResponseStatus",
]
