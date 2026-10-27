"""CloudApp: the OEM app identity a `TTLockCloud` presents to the TTLock cloud."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from .._cloud_helpers import DEFAULT_APP_ID, DEFAULT_APP_SECRET, DEFAULT_BASE_URL, DEFAULT_PACKAGE


@dataclass(frozen=True, slots=True)
class CloudApp:
    """One white-label TTLock app: the accounts it signs in are only visible to its own identity.

    `follows_regional_endpoint` is `False` for apps pinned to a single
    regional server, whose `base_url` must survive `discover_site()`.
    """

    app_id: str
    app_secret: str
    package_name: str
    base_url: str
    version: str
    platform: str
    follows_regional_endpoint: bool = True


DLOCK_XP = CloudApp(
    app_id=DEFAULT_APP_ID,
    app_secret=DEFAULT_APP_SECRET,
    package_name=DEFAULT_PACKAGE,
    base_url=DEFAULT_BASE_URL,
    version="2.2",
    platform="Android-1.6.0",
)

SCHLAGE_BREEZE = CloudApp(
    app_id="117e1efe3bbd403bb72f62759123801a",
    app_secret="eb6af53b570ea12517951d34df1e93fe",  # noqa: S106  -- public OEM secret embedded in the Breeze app
    package_name="com.breeze.lock",
    base_url="https://euservlet.ttlock.com",
    version="2.2",
    platform="iOS-2.3.0",
    follows_regional_endpoint=False,
)

CLOUD_APPS: MappingProxyType[str, CloudApp] = MappingProxyType(
    {
        "dlock_xp": DLOCK_XP,
        "schlage_breeze": SCHLAGE_BREEZE,
    }
)
