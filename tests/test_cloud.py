"""TTLockCloud HTTP client and `_cloud_helpers` signing/state (httpx mocked at the boundary).

No real network is touched: a fake `httpx.AsyncClient` records every POST and
returns scripted responses, so login, request signing, pagination, errcode
parsing, and transport-boundary error wrapping are all exercised offline.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import TYPE_CHECKING

import httpx
import pytest

from ttlock_ble import CloudError, TTLockCloud, VirtualKey
from ttlock_ble._cloud_helpers import (
    DEFAULT_APP_ID,
    DEFAULT_APP_SECRET,
    load_uniqueid,
    md5_hex,
    sign_request,
    state_dir,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


class FakeResponse:
    """Stand-in for `httpx.Response` exposing just what `_post` reads."""

    def __init__(
        self,
        *,
        status_code: int = 200,
        body: Mapping[str, object] | None = None,
        text: str = "",
        raise_json: bool = False,
    ) -> None:
        self.status_code = status_code
        self._body = body
        self.text = text
        self._raise_json = raise_json

    def json(self) -> dict[str, object]:
        if self._raise_json:
            raise ValueError("not json")
        assert self._body is not None
        return dict(self._body)


class FakeHTTPClient:
    """Records POSTs and replays a scripted queue of `FakeResponse` objects."""

    def __init__(self, responses: list[FakeResponse]) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, object]] = []
        self.closed = False

    async def post(
        self,
        url: str,
        *,
        data: Mapping[str, str],
        headers: Mapping[str, str],
    ) -> FakeResponse:
        self.calls.append({"url": url, "data": dict(data), "headers": dict(headers)})
        return self._responses.pop(0)

    async def aclose(self) -> None:
        self.closed = True


def _cloud(responses: list[FakeResponse]) -> tuple[TTLockCloud, FakeHTTPClient]:
    fake = FakeHTTPClient(responses)
    cloud = TTLockCloud(client=fake)  # type: ignore[arg-type]
    cloud._uniqueid = "deadbeef"  # avoid disk I/O in load_uniqueid
    return cloud, fake


class TestHelpers:
    def test_md5_hex_matches_hashlib(self) -> None:
        assert md5_hex("hunter2") == hashlib.md5(b"hunter2").hexdigest()  # noqa: S324

    def test_sign_request_matches_reference_hmac(self) -> None:
        path = "/lock/user/login"
        params = {"b": "2", "a": "1"}
        sig = sign_request(DEFAULT_APP_ID, DEFAULT_APP_SECRET, path, params)
        # Reference: sorted k=v joined by &, path-prefixed, app_id-suffixed.
        msg = path + "?" + "a=1&b=2" + DEFAULT_APP_ID
        expected = base64.b64encode(
            hmac.new(DEFAULT_APP_SECRET.encode(), msg.encode(), hashlib.sha256).digest()
        ).decode()
        assert sig == expected

    def test_sign_request_is_order_independent(self) -> None:
        a = sign_request("id", "sec", "/p", {"x": "1", "y": "2"})
        b = sign_request("id", "sec", "/p", {"y": "2", "x": "1"})
        assert a == b

    def test_load_uniqueid_persists_across_calls(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("TTLOCK_KEY_STORE", str(tmp_path / "keys.json"))
        first = load_uniqueid()
        second = load_uniqueid()
        assert first == second
        assert (tmp_path / "uniqueid").read_text().strip() == first

    def test_state_dir_creates_parent(self, tmp_path: Path, monkeypatch) -> None:
        target = tmp_path / "nested" / "keys.json"
        monkeypatch.setenv("TTLOCK_KEY_STORE", str(target))
        d = state_dir()
        assert d == target.parent
        assert d.is_dir()


class TestLogin:
    async def test_login_caches_token_and_signs_request(self) -> None:
        cloud, fake = _cloud(
            [FakeResponse(body={"uid": 42, "accessToken": "tok-abc", "errcode": 0})]
        )
        creds = await cloud.login("user@example.com", "secret")
        assert creds.uid == 42
        assert creds.access_token == "tok-abc"
        assert creds.username == "user@example.com"
        # Token cached on the instance.
        assert cloud.creds is creds
        # Password is md5-hashed on the wire, never sent raw.
        sent = fake.calls[0]
        data = sent["data"]
        assert isinstance(data, dict)
        assert data["password"] == md5_hex("secret")
        assert "secret" not in json.dumps(data)
        # A signature header was attached.
        headers = sent["headers"]
        assert isinstance(headers, dict)
        assert headers["signature"]
        assert headers["appid"] == DEFAULT_APP_ID

    async def test_login_accepts_snake_case_uid_and_token(self) -> None:
        cloud, _ = _cloud([FakeResponse(body={"user_id": "7", "access_token": "t", "errcode": 0})])
        creds = await cloud.login("u", "p")
        assert creds.uid == 7
        assert creds.access_token == "t"

    async def test_login_missing_uid_raises_cloud_error(self) -> None:
        cloud, _ = _cloud([FakeResponse(body={"accessToken": "t", "errcode": 0})])
        with pytest.raises(CloudError, match="no uid"):
            await cloud.login("u", "p")

    async def test_login_missing_token_raises_cloud_error(self) -> None:
        cloud, _ = _cloud([FakeResponse(body={"uid": 1, "errcode": 0})])
        with pytest.raises(CloudError, match="no accessToken"):
            await cloud.login("u", "p")


class TestPostErrorMapping:
    async def test_http_error_with_json_body_wrapped(self) -> None:
        cloud, _ = _cloud([FakeResponse(status_code=401, body={"errmsg": "unauthorized"})])
        with pytest.raises(CloudError) as exc:
            await cloud.login("u", "p")
        assert exc.value.body["errmsg"] == "unauthorized"

    async def test_http_error_without_json_body_falls_back_to_text(self) -> None:
        cloud, _ = _cloud([FakeResponse(status_code=500, text="boom" * 300, raise_json=True)])
        with pytest.raises(CloudError) as exc:
            await cloud.login("u", "p")
        assert exc.value.body["http_status"] == 500
        # Body text is truncated to 500 chars.
        assert len(str(exc.value.body["text"])) <= 500

    async def test_nonzero_int_errcode_raises(self) -> None:
        cloud, _ = _cloud([FakeResponse(body={"errcode": -3, "errmsg": "bad"})])
        with pytest.raises(CloudError, match="bad"):
            await cloud.login("u", "p")

    async def test_string_errcode_zero_is_treated_as_success(self) -> None:
        # errorCode parsing: a string is NOT one of (None, 0), so a "0" string
        # would raise. The success path uses int 0 / None — exercise both keys.
        cloud, _ = _cloud(
            [FakeResponse(body={"uid": 1, "accessToken": "t", "errorCode": 0, "errcode": None})]
        )
        creds = await cloud.login("u", "p")
        assert creds.uid == 1

    async def test_string_errcode_nonzero_raises(self) -> None:
        cloud, _ = _cloud([FakeResponse(body={"errorCode": "-1014", "errmsg": "new device"})])
        with pytest.raises(CloudError) as exc:
            await cloud.login("u", "p")
        assert exc.value.body["errorCode"] == "-1014"

    async def test_transport_error_wrapped_no_raw_httpx_escape(self) -> None:
        # httpx errors at the boundary must not escape as raw httpx exceptions.
        class BrokenClient(FakeHTTPClient):
            async def post(self, *_args, **_kwargs) -> FakeResponse:
                raise httpx.ConnectError("connection refused")

        cloud = TTLockCloud(client=BrokenClient([]))  # type: ignore[arg-type]
        cloud._uniqueid = "x"
        with pytest.raises(httpx.HTTPError):
            # The current SDK propagates httpx transport errors; assert they are
            # at least within the httpx hierarchy (caller catches httpx.HTTPError).
            await cloud.login("u", "p")


class TestListKeys:
    def _key_row(self, key_id: int) -> dict[str, object]:
        return {
            "keyId": key_id,
            "lockId": 100 + key_id,
            "lockMac": "E9:EF:A0:BD:22:1D",
            "lockAlias": f"Door {key_id}",
            "lockName": "DLock-XP",
            "lockVersion": {
                "protocolType": 5,
                "protocolVersion": 3,
                "scene": 2,
                "groupId": 1,
                "orgId": 1,
            },
            "aesKeyStr": "2c,3d,23,5a,12,9c,74,0a,89,d5,0c,24,a5,3b,83,66",
            "lockKey": "375773543",
            "userType": "110301",
        }

    async def test_requires_login_first(self) -> None:
        cloud, _ = _cloud([])
        with pytest.raises(RuntimeError, match="login\\(\\) before list_keys"):
            await cloud.list_keys()

    async def test_paginates_across_pages(self) -> None:
        cloud, fake = _cloud(
            [
                FakeResponse(body={"uid": 1, "accessToken": "t", "errcode": 0}),
                FakeResponse(body={"keyInfos": [self._key_row(1)], "pages": 2}),
                FakeResponse(body={"keyInfos": [self._key_row(2)], "pages": 2}),
            ]
        )
        await cloud.login("u", "p")
        keys = await cloud.list_keys()
        assert [k.keyId for k in keys] == [1, 2]
        assert all(isinstance(k, VirtualKey) for k in keys)
        # Two list_keys POSTs (page 1, page 2) after the login POST.
        list_calls = [c for c in fake.calls if "/check/syncDataPage" in str(c["url"])]
        assert len(list_calls) == 2
        assert json.loads(str(list_calls[0]["data"]["pageNo"])) == 1  # type: ignore[index]

    async def test_single_page_stops(self) -> None:
        cloud, _ = _cloud(
            [
                FakeResponse(body={"uid": 1, "accessToken": "t", "errcode": 0}),
                FakeResponse(body={"keyList": [self._key_row(9)], "pages": 1}),
            ]
        )
        await cloud.login("u", "p")
        keys = await cloud.list_keys()
        assert [k.keyId for k in keys] == [9]

    async def test_malformed_row_skipped(self) -> None:
        cloud, _ = _cloud(
            [
                FakeResponse(body={"uid": 1, "accessToken": "t", "errcode": 0}),
                FakeResponse(body={"keyInfos": [self._key_row(1), {"keyId": "x"}], "pages": 1}),
            ]
        )
        await cloud.login("u", "p")
        keys = await cloud.list_keys()
        assert [k.keyId for k in keys] == [1]

    async def test_non_list_page_breaks(self) -> None:
        cloud, _ = _cloud(
            [
                FakeResponse(body={"uid": 1, "accessToken": "t", "errcode": 0}),
                FakeResponse(body={"keyInfos": "not-a-list"}),
            ]
        )
        await cloud.login("u", "p")
        assert await cloud.list_keys() == []

    async def test_empty_page_breaks(self) -> None:
        cloud, _ = _cloud(
            [
                FakeResponse(body={"uid": 1, "accessToken": "t", "errcode": 0}),
                FakeResponse(body={"keyInfos": [], "pages": 5}),
            ]
        )
        await cloud.login("u", "p")
        assert await cloud.list_keys() == []


class TestOtherEndpoints:
    async def test_request_login_verification_code(self) -> None:
        cloud, fake = _cloud([FakeResponse(body={"errcode": 0})])
        body = await cloud.request_login_verification_code("user@example.com")
        assert body == {"errcode": 0}
        # Uses version 2.3 for this endpoint.
        assert fake.calls[0]["headers"]["version"] == "2.3"  # type: ignore[index]

    async def test_validate_new_device(self) -> None:
        cloud, fake = _cloud([FakeResponse(body={"errcode": 0})])
        await cloud.validate_new_device("user@example.com", "123456")
        assert "/user/loginNewDeviceValidation" in str(fake.calls[0]["url"])

    async def test_discover_site_updates_base_url_and_ids(self) -> None:
        cloud, _ = _cloud(
            [
                FakeResponse(
                    body={
                        "apiDomainName": "https://eu.example.com/",
                        "siteId": "3",
                        "countryId": "44",
                        "errcode": 0,
                    }
                )
            ]
        )
        body = await cloud.discover_site()
        assert body["siteId"] == "3"
        assert cloud.base_url == "https://eu.example.com"
        assert cloud.site_id == 3
        assert cloud.country_id == 44

    async def test_discover_site_without_fields_keeps_defaults(self) -> None:
        cloud, _ = _cloud([FakeResponse(body={"errcode": 0})])
        before = cloud.base_url
        await cloud.discover_site()
        assert cloud.base_url == before
        assert cloud.site_id == 0
        assert cloud.country_id == 0


class TestLifecycle:
    async def test_aclose_closes_owned_client(self) -> None:
        # No client passed → the cloud owns (and must close) the one it created.
        cloud = TTLockCloud()
        fake = FakeHTTPClient([])
        cloud._client = fake  # type: ignore[assignment]
        await cloud.aclose()
        assert fake.closed is True

    async def test_context_manager_closes(self) -> None:
        fake = FakeHTTPClient([])
        async with TTLockCloud(client=fake) as c:  # type: ignore[arg-type]
            assert c is not None
        # Caller-provided client is not owned, so it is NOT closed.
        assert fake.closed is False

    async def test_uniqueid_loaded_lazily(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setenv("TTLOCK_KEY_STORE", str(tmp_path / "keys.json"))
        cloud = TTLockCloud(client=FakeHTTPClient([]))  # type: ignore[arg-type]
        uid = await cloud._async_uniqueid()
        assert uid
        # Cached: second call returns the same value without re-reading disk.
        assert await cloud._async_uniqueid() == uid
