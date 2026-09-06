"""VirtualKey: per-(user, lock) record holding everything BLE needs to authenticate."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, cast

from ..crypto import decode_password
from .lock_version import LockVersion

if TYPE_CHECKING:
    from collections.abc import Mapping

USER_TYPE_ADMIN = "110301"


def _to_int(value: object, default: int = 0) -> int:
    """Coerce a JSON scalar (int/str/None) into an int, with a fallback."""
    if value is None or value == "":
        return default
    return int(str(value))


@dataclass(slots=True)
class VirtualKey:
    """Per-(user, lock) credential bundle.

    The cloud's `/check/syncDataPage` returns one of these per lock the
    user has been granted access to. We keep only the subset needed to
    drive BLE authentication.
    """

    keyId: int
    lockId: int
    lockMac: str
    lockAlias: str
    lockName: str
    lockVersion: LockVersion
    aesKeyStr: str
    unlockKey: str
    lockFlagPos: int
    timezoneRawOffSet: int
    startTime: int = 0
    endTime: int = 0
    keyType: int = 0
    userType: str = ""
    adminPs: str = ""
    keyboardPwdVersion: int = 0
    specialValue: int = 0
    featureValue: str = ""
    uid: int = 0

    @classmethod
    def from_cloud(cls, payload: Mapping[str, object], uid: int) -> VirtualKey:
        """Build a `VirtualKey` from a single `keyInfos[i]` dict in the cloud sync.

        Cloud-encoded fields (`lockKey`, `noKeyPwd`, `adminPwd`) are decoded
        eagerly so downstream code only sees the plain numeric strings the
        BLE protocol expects.
        """
        lock_key_field = (
            payload.get("lockKey") or payload.get("noKeyPwd") or payload.get("unlockKey") or ""
        )
        admin_field = payload.get("adminPwd") or payload.get("adminPs") or ""
        lock_version_raw = payload["lockVersion"]
        return cls(
            keyId=_to_int(payload["keyId"]),
            lockId=_to_int(payload["lockId"]),
            lockMac=str(payload["lockMac"]),
            lockAlias=str(payload.get("lockAlias", "")),
            lockName=str(payload.get("lockName", "")),
            lockVersion=LockVersion.parse(cast("Mapping[str, object]", lock_version_raw)),
            aesKeyStr=str(payload["aesKeyStr"]),
            unlockKey=decode_password(str(lock_key_field)),
            lockFlagPos=_to_int(payload.get("lockFlagPos", 0)),
            timezoneRawOffSet=_to_int(payload.get("timezoneRawOffSet", 0)),
            startTime=_to_int(payload.get("startDate", 0)),
            endTime=_to_int(payload.get("endDate", 0)),
            keyType=_to_int(payload.get("keyType", 0)),
            userType=str(payload.get("userType", "")),
            adminPs=decode_password(str(admin_field)),
            keyboardPwdVersion=_to_int(payload.get("keyboardPwdVersion", 0)),
            specialValue=_to_int(payload.get("specialValue", 0)),
            featureValue=str(payload.get("featureValue") or ""),
            uid=uid,
        )

    def is_admin(self) -> bool:
        """Return True if this key carries admin privileges on the lock."""
        return self.userType == USER_TYPE_ADMIN

    @property
    def feature_mask(self) -> int:
        """The lock's capability bits as one integer - see `LockFeature` for the positions.

        `featureValue` is the cloud's hex string and carries every bit;
        when a key predates it (or the cloud left it empty) the 32-bit
        `specialValue` stands in, exactly as the official app falls back
        to `Integer.toHexString(feature)`. Bits above 31 are then unknown
        and read as unset.
        """
        try:
            return int(self.featureValue, 16)
        except ValueError:
            return self.specialValue & 0xFFFFFFFF

    def has_feature(self, feature: int) -> bool:
        """Return True if the lock advertises `feature` (a `LockFeature` bit index).

        Mirrors `FeatureValueUtil.isSupportFeature` in the official SDK.
        An unset bit is not proof the lock lacks the capability when only
        the truncated `specialValue` is available - see `feature_mask`.
        """
        return bool(self.feature_mask >> feature & 1)

    def to_dict(self) -> dict[str, object]:
        """Serialise to a plain dict (used by the local key cache)."""
        data = asdict(self)
        data["lockVersion"] = asdict(self.lockVersion)
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> VirtualKey:
        """Reverse of `to_dict()` — used to load the cached keys.json."""
        kwargs = dict(data)
        lock_version_dict = cast("Mapping[str, object]", kwargs["lockVersion"])
        kwargs["lockVersion"] = LockVersion(
            protocolType=_to_int(lock_version_dict["protocolType"]),
            protocolVersion=_to_int(lock_version_dict["protocolVersion"]),
            scene=_to_int(lock_version_dict["scene"]),
            groupId=_to_int(lock_version_dict["groupId"]),
            orgId=_to_int(lock_version_dict["orgId"]),
        )
        return cls(**kwargs)  # type: ignore[arg-type]
