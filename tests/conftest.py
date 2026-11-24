"""Shared fixtures: the synthetic VirtualKey and the patched BLE connect every suite uses."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

import ttlock_ble.ble.transport as transport_mod
from ttlock_ble import LockVersion, VirtualKey

if TYPE_CHECKING:
    from collections.abc import Callable

SYNTHETIC_AES_KEY_STR = "a1,b2,c3,d4,e5,f6,07,18,29,3a,4b,5c,6d,7e,8f,90"
SYNTHETIC_LOCK_MAC = "AA:BB:CC:11:22:33"
SYNTHETIC_LOCK_ALIAS = "Test Lock"


def make_virtual_key() -> VirtualKey:
    return VirtualKey(
        keyId=1,
        lockId=2,
        lockMac=SYNTHETIC_LOCK_MAC,
        lockAlias=SYNTHETIC_LOCK_ALIAS,
        lockName="DLock-XP",
        lockVersion=LockVersion(protocolType=5, protocolVersion=3, scene=2, groupId=1, orgId=1),
        aesKeyStr=SYNTHETIC_AES_KEY_STR,
        unlockKey="246813579",
        lockFlagPos=0,
        timezoneRawOffSet=-10800000,
        userType="110301",
        adminPs="135792468",
    )


@pytest.fixture
def patched_connect(monkeypatch: pytest.MonkeyPatch) -> Callable[[object], None]:
    """Patch establish_connection to hand back the given fake bleak client."""

    def _install(fake: object) -> None:
        async def _establish(*_args: object, **_kwargs: object) -> object:
            return fake

        monkeypatch.setattr(transport_mod, "establish_connection", _establish)

    return _install
