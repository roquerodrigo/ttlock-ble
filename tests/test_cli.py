"""`ttlock` CLI commands (typer CliRunner) with the cloud + BLE client mocked.

No network, no BLE: `TTLockCloud` and `TTLockClient` are patched so each
command's argument parsing, key-store I/O, and output formatting are exercised
against an in-memory key cache written to a tmp path.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

import pytest
from typer.testing import CliRunner

from ttlock_ble import LockState, LockVersion, VirtualKey
from ttlock_ble._cloud_helpers import ERR_NEW_DEVICE_LOGIN
from ttlock_ble.exceptions import CloudError

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()


def _virtual_key() -> VirtualKey:
    return VirtualKey(
        keyId=1,
        lockId=2,
        lockMac="E9:EF:A0:BD:22:1D",
        lockAlias="Apto. 2616",
        lockName="DLock-XP",
        lockVersion=LockVersion(protocolType=5, protocolVersion=3, scene=2, groupId=1, orgId=1),
        aesKeyStr="2c,3d,23,5a,12,9c,74,0a,89,d5,0c,24,a5,3b,83,66",
        unlockKey="375773543",
        lockFlagPos=0,
        timezoneRawOffSet=-10800000,
        userType="110301",
        adminPs="422531259",
    )


@pytest.fixture
def cli_app(tmp_path: Path, monkeypatch):
    """Import the CLI fresh with KEY_STORE pointed at a tmp file."""
    store = tmp_path / "keys.json"
    monkeypatch.setenv("TTLOCK_KEY_STORE", str(store))
    monkeypatch.setenv("TTLOCK_EMAIL", "user@example.com")
    monkeypatch.setenv("TTLOCK_PASSWORD", "secret")
    import importlib

    from ttlock_ble import cli as cli_module

    importlib.reload(cli_module)
    return cli_module, store


def _write_keys(store: Path) -> None:
    store.parent.mkdir(parents=True, exist_ok=True)
    store.write_text(json.dumps([_virtual_key().to_dict()]))


class TestSync:
    def test_sync_saves_keys(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        fake_cloud = MagicMock()
        fake_cloud.discover_site = AsyncMock()
        fake_cloud.login = AsyncMock(return_value=MagicMock(uid=42))
        fake_cloud.list_keys = AsyncMock(return_value=[_virtual_key()])
        fake_cloud.__aenter__ = AsyncMock(return_value=fake_cloud)
        fake_cloud.__aexit__ = AsyncMock(return_value=None)
        monkeypatch.setattr(cli_module, "TTLockCloud", lambda: fake_cloud)

        result = runner.invoke(cli_module.app, ["sync", "-v"])
        assert result.exit_code == 0, result.output
        assert "saved" in result.output
        assert "uid=42" in result.output
        assert store.exists()

    def test_sync_site_discovery_failure_warns_and_continues(self, cli_app, monkeypatch) -> None:
        cli_module, _ = cli_app
        fake_cloud = MagicMock()
        fake_cloud.discover_site = AsyncMock(side_effect=CloudError({"errmsg": "no site"}))
        fake_cloud.login = AsyncMock(return_value=MagicMock(uid=1))
        fake_cloud.list_keys = AsyncMock(return_value=[])
        fake_cloud.__aenter__ = AsyncMock(return_value=fake_cloud)
        fake_cloud.__aexit__ = AsyncMock(return_value=None)
        monkeypatch.setattr(cli_module, "TTLockCloud", lambda: fake_cloud)

        result = runner.invoke(cli_module.app, ["sync"])
        assert result.exit_code == 0, result.output
        assert "site discovery failed" in result.output

    def test_sync_new_device_requests_code_and_exits_2(self, cli_app, monkeypatch) -> None:
        cli_module, _ = cli_app
        fake_cloud = MagicMock()
        fake_cloud.discover_site = AsyncMock()
        fake_cloud.login = AsyncMock(side_effect=CloudError({"errorCode": ERR_NEW_DEVICE_LOGIN}))
        fake_cloud.request_login_verification_code = AsyncMock()
        fake_cloud.__aenter__ = AsyncMock(return_value=fake_cloud)
        fake_cloud.__aexit__ = AsyncMock(return_value=None)
        monkeypatch.setattr(cli_module, "TTLockCloud", lambda: fake_cloud)

        result = runner.invoke(cli_module.app, ["sync"])
        assert result.exit_code == 2
        assert "verify" in result.output
        fake_cloud.request_login_verification_code.assert_awaited_once()

    def test_sync_other_login_error_propagates(self, cli_app, monkeypatch) -> None:
        cli_module, _ = cli_app
        fake_cloud = MagicMock()
        fake_cloud.discover_site = AsyncMock()
        fake_cloud.login = AsyncMock(side_effect=CloudError({"errmsg": "wrong password"}))
        fake_cloud.__aenter__ = AsyncMock(return_value=fake_cloud)
        fake_cloud.__aexit__ = AsyncMock(return_value=None)
        monkeypatch.setattr(cli_module, "TTLockCloud", lambda: fake_cloud)

        result = runner.invoke(cli_module.app, ["sync"])
        assert result.exit_code != 0
        assert isinstance(result.exception, CloudError)

    def test_sync_missing_credentials_errors(self, cli_app, monkeypatch) -> None:
        cli_module, _ = cli_app
        monkeypatch.delenv("TTLOCK_EMAIL", raising=False)
        monkeypatch.delenv("TTLOCK_PASSWORD", raising=False)
        # Stop dotenv from re-populating from a real .env file.
        monkeypatch.setattr(cli_module, "load_dotenv", lambda: None)
        result = runner.invoke(cli_module.app, ["sync"])
        assert result.exit_code != 0


class TestVerify:
    def test_verify_registers_device(self, cli_app, monkeypatch) -> None:
        cli_module, _ = cli_app
        fake_cloud = MagicMock()
        fake_cloud.discover_site = AsyncMock()
        fake_cloud.validate_new_device = AsyncMock()
        fake_cloud.__aenter__ = AsyncMock(return_value=fake_cloud)
        fake_cloud.__aexit__ = AsyncMock(return_value=None)
        monkeypatch.setattr(cli_module, "TTLockCloud", lambda: fake_cloud)

        result = runner.invoke(cli_module.app, ["verify", "123456", "-v"])
        assert result.exit_code == 0, result.output
        assert "registered" in result.output
        fake_cloud.validate_new_device.assert_awaited_once_with("user@example.com", "123456")

    def test_verify_suppresses_discover_error(self, cli_app, monkeypatch) -> None:
        cli_module, _ = cli_app
        fake_cloud = MagicMock()
        fake_cloud.discover_site = AsyncMock(side_effect=CloudError({"errmsg": "x"}))
        fake_cloud.validate_new_device = AsyncMock()
        fake_cloud.__aenter__ = AsyncMock(return_value=fake_cloud)
        fake_cloud.__aexit__ = AsyncMock(return_value=None)
        monkeypatch.setattr(cli_module, "TTLockCloud", lambda: fake_cloud)

        result = runner.invoke(cli_module.app, ["verify", "000000"])
        assert result.exit_code == 0, result.output


class TestKeyStore:
    def test_list_no_store_errors(self, cli_app) -> None:
        cli_module, _ = cli_app
        result = runner.invoke(cli_module.app, ["list"])
        assert result.exit_code != 0
        assert "sync" in result.output

    def test_list_prints_keys(self, cli_app) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        result = runner.invoke(cli_module.app, ["list"])
        assert result.exit_code == 0, result.output
        assert "lockId=2" in result.output
        assert "admin" in result.output

    def test_resolve_unknown_target_errors(self, cli_app) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        result = runner.invoke(cli_module.app, ["unlock", "9999"])
        assert result.exit_code != 0
        assert "No key matches" in result.output


class TestBleCommands:
    def _patch_client(self, cli_module, monkeypatch, client: MagicMock) -> None:
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)
        monkeypatch.setattr(cli_module, "TTLockClient", lambda _key: client)

    def test_unlock(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.unlock = AsyncMock()
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["unlock", "2", "-v"])
        assert result.exit_code == 0, result.output
        assert "unlocked" in result.output
        client.unlock.assert_awaited_once()

    def test_lock_by_alias(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.lock = AsyncMock()
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["lock", "Apto. 2616", "-v"])
        assert result.exit_code == 0, result.output
        assert "locked" in result.output

    def test_state(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.query_state = AsyncMock(return_value=(LockState.LOCKED, 87))
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["state", "E9:EF:A0:BD:22:1D", "-v"])
        assert result.exit_code == 0, result.output
        assert "LOCKED" in result.output
        assert "87%" in result.output

    def test_state_unknown(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.query_state = AsyncMock(return_value=(None, None))
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["state", "2"])
        assert result.exit_code == 0, result.output
        assert "UNKNOWN" in result.output
        assert "?" in result.output

    def test_battery(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.query_state = AsyncMock(return_value=(LockState.UNLOCKED, 55))
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["battery", "2", "-v"])
        assert result.exit_code == 0, result.output
        assert "55%" in result.output

    def test_battery_unknown_exits_1(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.query_state = AsyncMock(return_value=(LockState.LOCKED, None))
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["battery", "2"])
        assert result.exit_code == 1
        assert "unknown" in result.output
