"""Active BLE scan that resolves a lock's MAC to a `BLEDevice`."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from bleak import BleakScanner

if TYPE_CHECKING:
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData

# The BLE layer keeps logging under `ttlock_ble.client`: the logger name is
# what downstream users scope log levels with, and splitting the module out
# must not silently move their filters.
log: logging.Logger = logging.getLogger("ttlock_ble.client")

_SCAN_POLL_INTERVAL = 0.5


async def find_lock_device(mac: str, scan_timeout: float) -> BLEDevice | None:
    """Locate the lock in a way that works on macOS (which hides MACs).

    Match priority:
      1. exact MAC (works on Linux/Windows), then
      2. the last 3 octets of the MAC appearing as a hex suffix in the
         device's advertised name (`S534_1d22bd` for `…22:1D`).

    Falls back to `None` rather than connecting to a neighbour's lock.
    """
    target = mac.upper()
    suffix_bytes = bytes.fromhex(target.replace(":", ""))[-3:][::-1].hex()
    log.info("Scanning %.0fs for %s (MAC suffix '%s')…", scan_timeout, target, suffix_bytes)
    match: list[BLEDevice] = []
    loop = asyncio.get_running_loop()
    deadline = loop.time() + scan_timeout

    # bleak types AdvertisementData.platform_data as tuple[Any, ...], so the
    # callback signature carries an Any this side cannot annotate away.
    def _on_detection(  # type: ignore[explicit-any]
        dev: BLEDevice,
        adv: AdvertisementData,
    ) -> None:
        name = dev.name or adv.local_name or ""
        mac_match = dev.address.upper() == target or suffix_bytes in name.lower()
        if mac_match and not match:
            log.info("Lock found: %s rssi=%d", name or dev.address, adv.rssi)
            match.append(dev)

    async with BleakScanner(detection_callback=_on_detection):
        # Polling-with-sleep on purpose: we want to break as soon as
        # `_on_detection` fires, but bleak's scanner doesn't expose an
        # asyncio.Event for that — the callback runs synchronously.
        while not match and loop.time() < deadline:  # noqa: ASYNC110
            await asyncio.sleep(_SCAN_POLL_INTERVAL)
    return match[0] if match else None
