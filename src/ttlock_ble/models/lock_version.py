"""LockVersion record decoded from the cloud's lockVersion JSON object."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping


@dataclass(frozen=True, slots=True)
class LockVersion:
    """Identifies a lock's firmware family (protocol, scene, organization).

    The cloud serialises this as a JSON object on every key; the BLE
    protocol uses these five integers to assemble the V3 frame header.
    """

    protocolType: int
    protocolVersion: int
    scene: int
    groupId: int
    orgId: int

    @classmethod
    def parse(cls, raw: str | Mapping[str, object]) -> LockVersion:
        """Build a `LockVersion` from a JSON string or already-parsed mapping."""
        data: Mapping[str, object] = json.loads(raw) if isinstance(raw, str) else raw
        return cls(
            protocolType=int(str(data["protocolType"])),
            protocolVersion=int(str(data["protocolVersion"])),
            scene=int(str(data["scene"])),
            groupId=int(str(data.get("groupId", 0))),
            orgId=int(str(data.get("orgId", 0))),
        )

    def lock_type(self) -> int:  # noqa: PLR0911  -- mirrors the Java SDK switch verbatim
        """Map the (protocolType, protocolVersion, scene) triple to a lockType.

        Mirrors `com.ttlock.bl.sdk.command.Command.generateLockType` in the
        Android SDK; lockType drives the per-firmware command builders.
        """
        pt, sv, sc = self.protocolType, self.protocolVersion, self.scene
        if pt == 5 and sv == 3 and sc == 7:
            return 8
        if pt == 10 and sv == 1:
            return 6
        if pt == 5 and sv == 3:
            return 5
        if pt == 5 and sv == 4:
            return 4
        if pt == 5 and sv == 1:
            return 3
        if pt == 11 and sv == 1:
            return 7
        return 5
