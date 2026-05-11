"""TTLockCloud: async HTTP client for the TTLock OEM cloud (`servlet.ttlock.com`).

Bootstraps the credentials a `TTLockClient` needs to drive an
already-paired lock over BLE: one-time login + new-device verification +
periodic key sync. All calls are async because Home Assistant
integrations (the primary consumer) require it; CLI scripts wrap the
client in `asyncio.run()`.
"""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING, Self, cast

import httpx

from ._cloud_helpers import (
    CODE_CHANNEL_DEFAULT,
    CODE_TYPE_NEW_DEVICE_LOGIN,
    DEFAULT_APP_ID,
    DEFAULT_APP_SECRET,
    DEFAULT_BASE_URL,
    DEFAULT_PACKAGE,
    load_uniqueid,
    md5_hex,
    sign_request,
)
from .exceptions import CloudError
from .models import CloudCredentials, VirtualKey

if TYPE_CHECKING:
    from collections.abc import Mapping

log: logging.Logger = logging.getLogger("ttlock_ble.cloud")


class TTLockCloud:
    """Async TTLock cloud client backed by `httpx.AsyncClient`.

    Use it from inside an asyncio event loop (Home Assistant integrations,
    FastAPI services, scripts wrapped in `asyncio.run`). The wire protocol
    mirrors what the official Android app sends.
    """

    def __init__(  # noqa: PLR0913  -- single keyword-only constructor for the cloud client
        self,
        *,
        app_id: str = DEFAULT_APP_ID,
        app_secret: str = DEFAULT_APP_SECRET,
        base_url: str = DEFAULT_BASE_URL,
        package_name: str = DEFAULT_PACKAGE,
        version: str = "2.2",
        platform: str = "Android-1.6.0",
        language: str = "en",
        timeout: float = 35.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """Configure the client.

        If `client` is provided, the caller owns its lifecycle; otherwise
        a private `httpx.AsyncClient` is created and closed on `aclose()`.
        """
        self.app_id = app_id
        self.app_secret = app_secret
        self.base_url = base_url.rstrip("/")
        self.package_name = package_name
        self.version = version
        self.platform = platform
        self.language = language
        self.creds: CloudCredentials | None = None
        self.site_id: int = 0
        self.country_id: int = 0
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._uniqueid = load_uniqueid()

    async def __aenter__(self) -> Self:
        """Enter `async with TTLockCloud() as c:` — returns self unchanged."""
        return self

    async def __aexit__(self, *_exc: object) -> None:
        """Close the underlying httpx.AsyncClient if we created it."""
        await self.aclose()

    async def aclose(self) -> None:
        """Release the underlying HTTP connection pool (only if owned)."""
        if self._owns_client:
            await self._client.aclose()

    async def login(
        self,
        username: str,
        password: str,
        *,
        country_id: int | None = None,
        site_id: int | None = None,
    ) -> CloudCredentials:
        """POST `/user/login` and cache the resulting access token."""
        params = {
            "username": username,
            "password": md5_hex(password),
            "platId": "1",
            "uniqueid": self._uniqueid,
            "packageName": self.package_name,
            "countryId": str(country_id if country_id is not None else self.country_id),
            "siteId": str(site_id if site_id is not None else self.site_id),
            "install": "install:com.dlock.smart",
        }
        body = await self._post("/user/login", params)
        uid_field = body.get("uid") or body.get("user_id") or body.get("userId")
        if uid_field is None:
            raise CloudError({"message": "no uid in login response", "raw": body})
        token = body.get("accessToken") or body.get("access_token")
        if not token:
            raise CloudError({"message": "no accessToken in login response", "raw": body})
        self.creds = CloudCredentials(
            uid=int(str(uid_field)),
            access_token=str(token),
            username=username,
        )
        return self.creds

    async def request_login_verification_code(
        self,
        account: str,
        *,
        channel: int = CODE_CHANNEL_DEFAULT,
    ) -> Mapping[str, object]:
        """POST `/user/sendValidationCode` to email/SMS a new-device-login code.

        Mirrors `VerificationCodeUtil.sendValidationCode(false, account, 4, 0, 1, …)`
        invoked by `TerifyLoginActivity` in the Android app.
        """
        params = {
            "account": account,
            "uniqueid": self._uniqueid,
            "codeType": str(CODE_TYPE_NEW_DEVICE_LOGIN),
            "xWidth": "0",
            "channel": str(channel),
            "language": self.language,
            "siteId": str(self.site_id),
        }
        return await self._post("/user/sendValidationCode", params, version="2.3")

    async def validate_new_device(
        self, account: str, verification_code: str
    ) -> Mapping[str, object]:
        """Submit the emailed/SMS code, registering this `uniqueid` with the server."""
        params = {
            "userid": account,
            "uniqueid": self._uniqueid,
            "verificationCode": verification_code,
            "platId": "1",
            "countryId": str(self.country_id),
            "siteId": str(self.site_id),
        }
        return await self._post("/user/loginNewDeviceValidation", params)

    async def discover_site(self) -> Mapping[str, object]:
        """Resolve the regional API base URL + site/country for our public IP."""
        body = await self._post("/system/getCountryAndSiteInfo", {"uniqueid": self._uniqueid})
        api = body.get("apiDomainName")
        if api:
            self.base_url = str(api).rstrip("/")
        site_field = body.get("siteId")
        if site_field is not None:
            self.site_id = int(str(site_field))
        country_field = body.get("countryId")
        if country_field is not None:
            self.country_id = int(str(country_field))
        return body

    async def list_keys(self) -> list[VirtualKey]:
        """Page through `/check/syncDataPage` and return every `VirtualKey` for this user."""
        if self.creds is None:
            raise RuntimeError("login() before list_keys()")
        keys: list[VirtualKey] = []
        page_no = 1
        user_info = json.dumps(
            {
                "appVersion": "1.6.0",
                "deviceName": "ttlock-ble",
                "language": self.language,
                "deviceSystemVersion": "Linux/macOS",
                "packageName": self.package_name,
            }
        )
        while True:
            body = await self._post(
                "/check/syncDataPage",
                {
                    "lastUpdateDate": "0",
                    "pageNo": str(page_no),
                    "userInfo": user_info,
                    "uniqueid": self._uniqueid,
                },
            )
            raw_page = body.get("keyInfos") or body.get("keyList") or []
            if not isinstance(raw_page, list):
                break
            page = cast("list[Mapping[str, object]]", raw_page)
            for item in page:
                try:
                    keys.append(VirtualKey.from_cloud(item, uid=self.creds.uid))
                except (KeyError, ValueError, TypeError) as exc:
                    log.warning("Skipping malformed key row: %s", exc)
            pages_field = body.get("pages") or body.get("pageNos") or 1
            pages = int(str(pages_field))
            if page_no >= pages or not page:
                break
            page_no += 1
        return keys

    async def _post(
        self,
        path: str,
        params: Mapping[str, str],
        *,
        version: str | None = None,
    ) -> dict[str, object]:
        params_full = {k: v for k, v in params.items() if v is not None}
        params_full.setdefault("date", str(int(time.time() * 1000)))
        params_full.setdefault("d", str(int(time.time() * 1000)))
        full_path = "/lock" + path
        signature = sign_request(self.app_id, self.app_secret, full_path, params_full)
        headers = {
            "appid": self.app_id,
            "appSecret": self.app_secret,
            "version": version or self.version,
            "platform": self.platform,
            "language": self.language,
            "packageName": self.package_name,
            "date": params_full["date"],
            "uniqueid": self._uniqueid,
            "signature": signature,
            "refer": "0",
            "User-Agent": "Mozilla/5.0 (Linux; Android 14; ttlock-ble) AppleWebKit/537.36",
            "accessToken": self.creds.access_token if self.creds else "",
            "operatorUid": str(self.creds.uid) if self.creds else "",
        }
        url = self.base_url + full_path
        resp = await self._client.post(url, data=params_full, headers=headers)
        if resp.status_code >= 400:
            try:
                err_body: dict[str, object] = resp.json()
            except ValueError:
                err_body = {"http_status": resp.status_code, "text": resp.text[:500]}
            raise CloudError(err_body)
        body: dict[str, object] = resp.json()
        if body.get("errcode") not in (None, 0) or body.get("errorCode") not in (None, 0):
            raise CloudError(body)
        return body
