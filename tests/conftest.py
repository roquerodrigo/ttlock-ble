"""Shared fixtures: the synthetic VirtualKey every suite builds clients from."""

from __future__ import annotations

from ttlock_ble import LockVersion, VirtualKey

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
