"""SiteInfo: regional API endpoints discovered from /system/getCountryAndSiteInfo."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping


@dataclass(frozen=True, slots=True)
class SiteInfo:
    """Per-region TTLock service URLs and identifiers."""

    siteId: int
    countryId: int
    apiDomainName: str
    gatewayDomainName: str = ""
    wifiLockDomainName: str = ""
    name: str = ""

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> SiteInfo:
        """Build a `SiteInfo` from a `/system/getCountryAndSiteInfo` JSON object."""
        api = payload.get("apiDomainName")
        return cls(
            siteId=int(str(payload.get("siteId", 0))),
            countryId=int(str(payload.get("countryId", 0))),
            apiDomainName=str(api) if api else "https://servlet.ttlock.com",
            gatewayDomainName=str(payload.get("gatewayDomainName", "")),
            wifiLockDomainName=str(payload.get("wifiLockDomainName", "")),
            name=str(payload.get("name", "")),
        )
