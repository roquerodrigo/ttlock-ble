"""The exported surface is the package's contract — pin it against drift.

Internal modules may be split or renamed freely (`CODE_STYLE.md`), but
anything listed here can only change with a `BREAKING CHANGE:` footer and a
coordinated release of the Home Assistant integration that consumes it.
"""

from __future__ import annotations

import inspect

import ttlock_ble
from ttlock_ble import TTLockClient

EXPECTED_EXPORTS = frozenset(
    {
        "AutoLockLimits",
        "AutoLockOperate",
        "CloudError",
        "DeviceInfo",
        "KeyboardPwdType",
        "LockAdvertisement",
        "LockEvent",
        "LockState",
        "LockVersion",
        "LockVolume",
        "LogEntry",
        "LogOperate",
        "PwdOperateType",
        "SiteInfo",
        "TTLockClient",
        "TTLockCloud",
        "TTLockError",
        "VirtualKey",
    }
)

EXPECTED_CLIENT_MEMBERS = frozenset(
    {
        "add_event_listener",
        "add_passcode",
        "calibrate_time",
        "clear_passcodes",
        "connect",
        "delete_passcode",
        "disconnect",
        "from_ble_device",
        "get_auto_lock_limits",
        "get_auto_lock_time",
        "get_device_info",
        "get_lock_time",
        "get_operation_log",
        "is_connected",
        "key",
        "lock",
        "query_state",
        "remove_event_listener",
        "scan_timeout",
        "set_auto_lock_time",
        "set_lock_sound",
        "set_lock_volume",
        "sync_time",
        "unlock",
    }
)


def test_package_exports_are_pinned() -> None:
    assert frozenset(ttlock_ble.__all__) == EXPECTED_EXPORTS
    for name in EXPECTED_EXPORTS:
        assert getattr(ttlock_ble, name, None) is not None


def test_client_public_members_are_pinned() -> None:
    from tests.conftest import make_virtual_key

    client = TTLockClient(make_virtual_key())
    members = {name for name in dir(client) if not name.startswith("_")}
    assert members == EXPECTED_CLIENT_MEMBERS


def test_client_signatures_are_pinned() -> None:
    assert str(inspect.signature(TTLockClient.__init__)) == (
        "(self, key: 'VirtualKey', *, device: 'BLEDevice | None' = None,"
        " scan_timeout: 'float' = 25.0,"
        " disconnected_callback: 'DisconnectedCallback | None' = None,"
        " keep_alive_after_command: 'float' = 25.0) -> 'None'"
    )
    assert str(inspect.signature(TTLockClient.from_ble_device)) == (
        "(device: 'BLEDevice', key: 'VirtualKey', *,"
        " disconnected_callback: 'DisconnectedCallback | None' = None,"
        " keep_alive_after_command: 'float' = 25.0) -> 'TTLockClient'"
    )


def test_scan_timeout_round_trips_through_the_transport() -> None:
    from tests.conftest import make_virtual_key

    client = TTLockClient(make_virtual_key(), scan_timeout=7.5)
    assert client.scan_timeout == 7.5
    client.scan_timeout = 3.0
    assert client._transport.scan_timeout == 3.0
