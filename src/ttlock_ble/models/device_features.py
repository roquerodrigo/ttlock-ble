"""DeviceFeatures: the capability mask a lock reports to `TTLockClient.get_device_features`."""

from __future__ import annotations

from dataclasses import dataclass

from ..constants import LockFeature


@dataclass(frozen=True, slots=True)
class DeviceFeatures:
    """The lock's own feature value, read over BLE rather than taken from the cloud.

    `mask` holds every bit the lock sent, so `supports(LockFeature.X)` is
    the same test the official app performs with `FeatureValueUtil` -
    without the 32-bit truncation `VirtualKey.specialValue` suffers from.
    `battery` is the percentage the lock reports alongside, the same way
    the auto-lock and fingerprint responses carry it.
    """

    mask: int
    battery: int

    def supports(self, feature: int) -> bool:
        """Return True if the lock advertises `feature` (a `LockFeature` bit index)."""
        return bool(self.mask >> feature & 1)

    @property
    def known(self) -> tuple[LockFeature, ...]:
        """The `LockFeature` members set in `mask`, in ascending bit order."""
        return tuple(feature for feature in LockFeature if self.supports(feature))

    @property
    def unnamed_bits(self) -> tuple[int, ...]:
        """Set bits with no `LockFeature` name - firmware newer than the SDK mirror."""
        named = {int(feature) for feature in LockFeature}
        return tuple(
            bit for bit in range(self.mask.bit_length()) if self.supports(bit) and bit not in named
        )

    @property
    def feature_value(self) -> str:
        """`mask` in the hex form the cloud uses for `VirtualKey.featureValue`.

        Mirrors the SDK's `convertToFeatureValue`: uppercase, no leading
        zeros, `"0"` when nothing is set - so it compares directly with
        the cloud's string.
        """
        return format(self.mask, "X")
