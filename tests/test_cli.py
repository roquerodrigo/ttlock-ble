"""`ttlock` CLI commands (typer CliRunner) with the cloud + BLE client mocked.

No network, no BLE: `TTLockCloud` and `TTLockClient` are patched so each
command's argument parsing, key-store I/O, and output formatting are exercised
against an in-memory key cache written to a tmp path.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

import pytest
from typer.testing import CliRunner

from tests.conftest import make_virtual_key
from ttlock_ble import (
    CLOUD_APPS,
    AutoLockLimits,
    CardEntry,
    CloudApp,
    Credential,
    CyclicSchedule,
    DeviceFeatures,
    DeviceInfo,
    DeviceProperties,
    FingerprintEntry,
    LockSound,
    LockState,
    LockVolume,
    PasscodeEntry,
    Period,
    Permanent,
    SingleUse,
    Weekly,
    WeeklyWindow,
)
from ttlock_ble._cloud_helpers import ERR_NEW_DEVICE_LOGIN
from ttlock_ble.constants import KeyboardPwdType, Weekday
from ttlock_ble.exceptions import CloudError

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()


_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _usage_error(app, arguments: list[str]) -> str:
    """Run a command expected to fail and return its message without styling or wrapping."""
    result = runner.invoke(app, arguments, env={"COLUMNS": "300"})
    assert result.exit_code != 0
    return _ANSI_ESCAPE.sub("", result.output)


_GUEST_ARRIVES = dt.datetime(2026, 12, 24, 18)  # noqa: DTZ001 -- lock-local wall clock
_GUEST_LEAVES = dt.datetime(2026, 12, 26, 12)  # noqa: DTZ001 -- lock-local wall clock


def _write_keys(store: Path) -> None:
    store.parent.mkdir(parents=True, exist_ok=True)
    store.write_text(json.dumps([make_virtual_key().to_dict()]))


def _patch_cloud(monkeypatch, cli_module, fake_cloud) -> list[CloudApp]:
    selected: list[CloudApp] = []

    def _for_app(app: CloudApp) -> MagicMock:
        selected.append(app)
        return fake_cloud

    monkeypatch.setattr(cli_module, "TTLockCloud", SimpleNamespace(for_app=_for_app))
    return selected


class TestSync:
    def test_sync_saves_keys(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        fake_cloud = MagicMock()
        fake_cloud.discover_site = AsyncMock()
        fake_cloud.login = AsyncMock(return_value=MagicMock(uid=42))
        fake_cloud.list_keys = AsyncMock(return_value=[make_virtual_key()])
        fake_cloud.__aenter__ = AsyncMock(return_value=fake_cloud)
        fake_cloud.__aexit__ = AsyncMock(return_value=None)
        _patch_cloud(monkeypatch, cli_module, fake_cloud)

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
        _patch_cloud(monkeypatch, cli_module, fake_cloud)

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
        _patch_cloud(monkeypatch, cli_module, fake_cloud)

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
        _patch_cloud(monkeypatch, cli_module, fake_cloud)

        result = runner.invoke(cli_module.app, ["sync"])
        assert result.exit_code != 0
        assert isinstance(result.exception, CloudError)

    def test_sync_signs_in_as_the_selected_app(self, cli_app, monkeypatch) -> None:
        cli_module, _ = cli_app
        fake_cloud = MagicMock()
        fake_cloud.discover_site = AsyncMock()
        fake_cloud.login = AsyncMock(return_value=MagicMock(uid=1))
        fake_cloud.list_keys = AsyncMock(return_value=[])
        fake_cloud.__aenter__ = AsyncMock(return_value=fake_cloud)
        fake_cloud.__aexit__ = AsyncMock(return_value=None)
        selected = _patch_cloud(monkeypatch, cli_module, fake_cloud)

        result = runner.invoke(cli_module.app, ["sync", "--app", "schlage_breeze"])
        assert result.exit_code == 0, result.output
        assert selected == [CLOUD_APPS["schlage_breeze"]]

    def test_sync_defaults_to_the_dlock_xp_app(self, cli_app, monkeypatch) -> None:
        cli_module, _ = cli_app
        fake_cloud = MagicMock()
        fake_cloud.discover_site = AsyncMock()
        fake_cloud.login = AsyncMock(return_value=MagicMock(uid=1))
        fake_cloud.list_keys = AsyncMock(return_value=[])
        fake_cloud.__aenter__ = AsyncMock(return_value=fake_cloud)
        fake_cloud.__aexit__ = AsyncMock(return_value=None)
        selected = _patch_cloud(monkeypatch, cli_module, fake_cloud)

        result = runner.invoke(cli_module.app, ["sync"])
        assert result.exit_code == 0, result.output
        assert selected == [CLOUD_APPS["dlock_xp"]]

    def test_sync_unknown_app_errors(self, cli_app) -> None:
        cli_module, _ = cli_app
        result = runner.invoke(cli_module.app, ["sync", "--app", "nope"])
        assert result.exit_code != 0
        assert "schlage_breeze" in result.output

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
        _patch_cloud(monkeypatch, cli_module, fake_cloud)

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
        _patch_cloud(monkeypatch, cli_module, fake_cloud)

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
        result = runner.invoke(cli_module.app, ["lock", "Test Lock", "-v"])
        assert result.exit_code == 0, result.output
        assert "locked" in result.output

    def test_state(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.query_state = AsyncMock(return_value=(LockState.LOCKED, 87))
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["state", "AA:BB:CC:11:22:33", "-v"])
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

    def test_sound_on(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.set_lock_sound = AsyncMock()
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["sound", "2", "on", "-v"])
        assert result.exit_code == 0, result.output
        assert "sound on" in result.output
        client.set_lock_sound.assert_awaited_once_with(enabled=True)

    def test_sound_off(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.set_lock_sound = AsyncMock()
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["sound", "2", "off"])
        assert result.exit_code == 0, result.output
        assert "sound off" in result.output
        client.set_lock_sound.assert_awaited_once_with(enabled=False)

    def test_sound_invalid_state_errors(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.set_lock_sound = AsyncMock()
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["sound", "2", "loud"])
        assert result.exit_code != 0
        client.set_lock_sound.assert_not_awaited()

    def test_get_sound(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.get_lock_sound = AsyncMock(
            return_value=LockSound(enabled=True, volume=LockVolume.MEDIUM_HIGH)
        )
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["get-sound", "2", "-v"])
        assert result.exit_code == 0, result.output
        assert "sound: on" in result.output
        assert "volume: 4 (MEDIUM_HIGH)" in result.output

    def test_get_sound_without_volume(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.get_lock_sound = AsyncMock(return_value=LockSound(enabled=False, volume=None))
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["get-sound", "2"])
        assert result.exit_code == 0, result.output
        assert "sound: off" in result.output
        assert "volume: not reported" in result.output

    def test_volume(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.set_lock_volume = AsyncMock()
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["volume", "2", "3", "-v"])
        assert result.exit_code == 0, result.output
        assert "volume set to 3" in result.output
        client.set_lock_volume.assert_awaited_once_with(3)

    def test_volume_out_of_range_errors_without_reaching_the_lock(
        self, cli_app, monkeypatch
    ) -> None:
        """A level the enum does not know is a typo, not a reason to wake a lock."""
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.set_lock_volume = AsyncMock()
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["volume", "2", "6"])
        assert result.exit_code != 0
        client.set_lock_volume.assert_not_awaited()

    def test_device_info(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.get_device_info = AsyncMock(
            return_value=DeviceInfo(
                manufacturer="Sciener",
                model="SN484",
                hardware_revision="1.2",
                firmware_revision="6.5.08.230228",
            )
        )
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["device-info", "2", "-v"])
        assert result.exit_code == 0, result.output
        assert "Sciener" in result.output
        assert "SN484" in result.output
        assert "1.2" in result.output
        assert "6.5.08.230228" in result.output

    def test_device_info_unconfirmed_fields_show_as_unknown(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.get_device_info = AsyncMock(return_value=DeviceInfo())
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["device-info", "2"])
        assert result.exit_code == 0, result.output
        assert "serial number:     ?" in result.output
        assert "software revision: ?" in result.output

    def test_features(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.get_device_features = AsyncMock(
            return_value=DeviceFeatures(mask=(1 << 0) | (1 << 22) | (1 << 26), battery=77)
        )
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["features", "2", "-v"])
        assert result.exit_code == 0, result.output
        assert "feature value: 4400001  battery: 77%" in result.output
        assert "  0  PASSCODE" in result.output
        assert " 22  PASSAGE_MODE" in result.output
        assert " 26  (no name in the SDK mirror)" in result.output
        assert "note:" not in result.output

    def test_features_flags_a_stale_cached_feature_value(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        cached = make_virtual_key().to_dict()
        cached["featureValue"] = "1"
        store.parent.mkdir(parents=True, exist_ok=True)
        store.write_text(json.dumps([cached]))
        client = MagicMock()
        client.get_device_features = AsyncMock(return_value=DeviceFeatures(mask=0x11, battery=50))
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["features", "2"])
        assert result.exit_code == 0, result.output
        assert "note: the cached eKey carries a different feature value (1)" in result.output

    def test_get_device_properties(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.get_device_properties = AsyncMock(
            return_value=DeviceProperties(
                model_variant="SN478_PV53",
                hardware_revision="1.2",
                firmware_version="6.4.43.240529",
                manufacture_date="2b6eaae3",
                mac_address="76:44:55:3D:0D:BC",
                clock_time=dt.datetime(2026, 8, 29, 23, 47, 52),  # noqa: DTZ001 -- lock RTC is naive
            )
        )
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["get-device-properties", "2", "-v"])
        assert result.exit_code == 0, result.output
        assert "SN478_PV53" in result.output
        assert "1.2" in result.output
        assert "6.4.43.240529" in result.output
        assert "2b6eaae3" in result.output
        assert "76:44:55:3D:0D:BC" in result.output
        assert "2026-08-29 23:47:52" in result.output

    def test_add_passcode(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.passcodes.add = AsyncMock()
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["add-passcode", "2", "1234", "-v"])
        assert result.exit_code == 0, result.output
        assert "1234 added" in result.output
        client.passcodes.add.assert_awaited_once_with("1234", Permanent())

    @pytest.mark.parametrize(
        ("options", "validity"),
        [
            (
                ["--start", "2026-12-24T18:00", "--end", "2026-12-26T12:00"],
                Period(_GUEST_ARRIVES, _GUEST_LEAVES),
            ),
            (
                ["--start", "2026-12-24T18:00", "--end", "2026-12-26T12:00", "--single-use"],
                SingleUse(_GUEST_ARRIVES, _GUEST_LEAVES),
            ),
            (
                ["--days", "weekend", "--from", "09:00", "--to", "12:00"],
                Weekly(
                    (
                        WeeklyWindow(Weekday.SATURDAY, dt.time(9), dt.time(12)),
                        WeeklyWindow(Weekday.SUNDAY, dt.time(9), dt.time(12)),
                    )
                ),
            ),
            (
                ["--days", "tue", "--from", "17:00", "--to", "19:00"],
                Weekly((WeeklyWindow(Weekday.TUESDAY, dt.time(17), dt.time(19)),)),
            ),
        ],
    )
    def test_add_passcode_with_validity(self, cli_app, monkeypatch, options, validity) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.passcodes.add = AsyncMock()
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["add-passcode", "2", "1234", *options])
        assert result.exit_code == 0, result.output
        client.passcodes.add.assert_awaited_once_with("1234", validity)

    @pytest.mark.parametrize(
        "extra",
        [["--start", "2026-12-24T18:00", "--end", "2026-12-26T12:00"], ["--single-use"]],
        ids=["dates", "single use"],
    )
    def test_weekly_passcode_refuses_dates_instead_of_dropping_them(self, cli_app, extra) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        weekly = ["--days", "mon", "--from", "08:00", "--to", "09:00"]
        message = _usage_error(cli_module.app, ["add-passcode", "2", "1234", *weekly, *extra])
        assert "without a date range" in message

    @pytest.mark.parametrize(
        ("options", "message"),
        [
            (["--start", "2026-12-24T18:00"], "go together"),
            (["--single-use"], "needs --start and --end"),
            (["--days", "weekend"], "needs --from and --to"),
            (["--days", "someday", "--from", "09:00", "--to", "12:00"], "comma-separated"),
            (["--days", "mon", "--from", "9h", "--to", "12:00"], "17:30"),
            (["--start", "tomorrow", "--end", "2026-12-26T12:00"], "2026-12-24T18:00"),
            (["--start", "2026-12-26T12:00", "--end", "2026-12-24T18:00"], "start before"),
        ],
    )
    def test_add_passcode_rejects_bad_validity(self, cli_app, options, message) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        assert message in _usage_error(cli_module.app, ["add-passcode", "2", "1234", *options])

    @pytest.mark.parametrize(
        ("arguments", "message"),
        [
            (["add-passcode", "2", "12a4"], "4-9 digits"),
            (
                [
                    "add-passcode",
                    "2",
                    "1234",
                    "--days",
                    "mon,wed",
                    "--from",
                    "08:00",
                    "--to",
                    "09:00",
                ],
                "one weekday",
            ),
            (
                ["add-passcode", "2", "1234", "--days", "mon", "--from", "08:00", "--to", "09:30"],
                "whole hours",
            ),
            (["modify-passcode", "2", "1234", "--new-code", "12"], "4-9 digits"),
            (["delete-passcode", "2", "12"], "4-9 digits"),
            (["set-admin-passcode", "2", "12", "-y"], "4-9 digits"),
        ],
    )
    def test_invalid_passcode_input_never_connects(
        self, cli_app, monkeypatch, arguments, message
    ) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        self._patch_client(cli_module, monkeypatch, client)
        assert message in _usage_error(cli_module.app, arguments)
        client.__aenter__.assert_not_called()

    def test_modify_passcode(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.passcodes.modify = AsyncMock()
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(
            cli_module.app,
            [
                "modify-passcode",
                "2",
                "1234",
                "--new-code",
                "5678",
                "--start",
                "2026-12-24T18:00",
                "--end",
                "2026-12-26T12:00",
                "-v",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "5678 updated" in result.output
        client.passcodes.modify.assert_awaited_once_with(
            "1234",
            new_code="5678",
            validity=Period(_GUEST_ARRIVES, _GUEST_LEAVES),
        )

    def test_modify_passcode_needs_a_change(self, cli_app) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        assert "--new-code" in _usage_error(cli_module.app, ["modify-passcode", "2", "1234"])

    def test_get_admin_passcode(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.admin_passcode.get = AsyncMock(return_value="246810")
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["get-admin-passcode", "2", "-v"])
        assert result.exit_code == 0, result.output
        assert result.output.strip() == "246810"

    def test_set_admin_passcode(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.admin_passcode.set = AsyncMock()
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(
            cli_module.app, ["set-admin-passcode", "2", "246810", "-v"], input="y\n"
        )
        assert result.exit_code == 0, result.output
        client.admin_passcode.set.assert_awaited_once_with("246810")

    def test_set_admin_passcode_aborts_without_confirmation(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.admin_passcode.set = AsyncMock()
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["set-admin-passcode", "2", "246810"], input="n\n")
        assert result.exit_code != 0
        client.admin_passcode.set.assert_not_awaited()

    def test_get_schedule_of_a_card(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.weekly_schedules.get = AsyncMock(
            return_value=(WeeklyWindow(Weekday.MONDAY, dt.time(8), dt.time(12)),)
        )
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["get-schedule", "2", "--card", "0a1b2c3d", "-v"])
        assert result.exit_code == 0, result.output
        assert "Monday    08:00-12:00" in result.output
        client.weekly_schedules.get.assert_awaited_once_with(Credential.card(0x0A1B2C3D))

    def test_get_schedule_without_windows_mentions_a_missing_credential(
        self, cli_app, monkeypatch
    ) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.weekly_schedules.get = AsyncMock(return_value=())
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(
            cli_module.app, ["get-schedule", "2", "--fingerprint", "0001e2400003"]
        )
        assert result.exit_code == 0, result.output
        assert "no weekly windows" in result.output
        assert "does not hold this credential" in result.output
        client.weekly_schedules.get.assert_awaited_once_with(
            Credential.fingerprint(bytes.fromhex("0001e2400003"))
        )

    @pytest.mark.parametrize(
        ("options", "message"),
        [
            ([], "exactly one of --card or --fingerprint"),
            (["--card", "00000001", "--fingerprint", "0001e2400003"], "exactly one"),
            (["--card", "000001"], "card id must be 4 or 8 bytes"),
            (["--card", "zz"], "credential id"),
            (["--fingerprint", "0001"], "6 bytes"),
        ],
    )
    def test_get_schedule_needs_one_valid_credential(self, cli_app, options, message) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        assert message in _usage_error(cli_module.app, ["get-schedule", "2", *options])

    def test_card_with_an_eight_byte_id_keeps_its_width(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.weekly_schedules.get = AsyncMock(return_value=())
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["get-schedule", "2", "--card", "000000000a1b2c3d"])
        assert result.exit_code == 0, result.output
        (credential,), _ = client.weekly_schedules.get.await_args
        assert credential.identifier == bytes.fromhex("000000000a1b2c3d")

    def test_set_schedule_rejects_a_repeated_weekday_before_connecting(
        self, cli_app, monkeypatch
    ) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        self._patch_client(cli_module, monkeypatch, client)
        arguments = [
            "set-schedule",
            "2",
            "--card",
            "00000001",
            "--window",
            "workdays=08:00-18:00",
            "--window",
            "mon=09:00-10:00",
            "--yes",
        ]
        assert "one window per weekday" in _usage_error(cli_module.app, arguments)
        client.__aenter__.assert_not_called()

    def test_set_schedule(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.get_cards = AsyncMock(
            return_value=[
                CardEntry(card_id=bytes.fromhex("0a1b2c3d"), start_date=None, end_date=None)
            ]
        )
        client.weekly_schedules.set = AsyncMock()
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(
            cli_module.app,
            [
                "set-schedule",
                "2",
                "--card",
                "0a1b2c3d",
                "--window",
                "weekend=09:00-12:00",
                "--window",
                "thu=18:30-22:00",
                "-v",
            ],
            input="y\n",
        )
        assert result.exit_code == 0, result.output
        assert "card 0a1b2c3d" in result.output
        assert "3 weekly window(s) set" in result.output
        client.weekly_schedules.set.assert_awaited_once_with(
            Credential.card(0x0A1B2C3D),
            (
                WeeklyWindow(Weekday.SATURDAY, dt.time(9), dt.time(12)),
                WeeklyWindow(Weekday.SUNDAY, dt.time(9), dt.time(12)),
                WeeklyWindow(Weekday.THURSDAY, dt.time(18, 30), dt.time(22)),
            ),
        )

    @pytest.mark.parametrize(
        ("window", "message"),
        [
            ("monday 8-12", "mon=08:00-12:00"),
            ("mon=12:00-08:00", "same day"),
            ("mon=8h-12:00", "17:30"),
        ],
    )
    def test_set_schedule_rejects_bad_windows(self, cli_app, window, message) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        arguments = ["set-schedule", "2", "--card", "00000001", "--window", window, "--yes"]
        assert message in _usage_error(cli_module.app, arguments)

    def test_set_schedule_refuses_a_card_the_lock_does_not_hold(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.get_cards = AsyncMock(return_value=[])
        client.weekly_schedules.set = AsyncMock()
        self._patch_client(cli_module, monkeypatch, client)
        arguments = ["set-schedule", "2", "--card", "0a1b2c3d", "--window", "mon=08:00-09:00", "-y"]
        assert "does not hold card 0a1b2c3d" in _usage_error(cli_module.app, arguments)
        client.weekly_schedules.set.assert_not_awaited()

    def test_set_schedule_checks_fingerprints_for_a_fingerprint(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.get_fingerprints = AsyncMock(
            return_value=[
                FingerprintEntry(
                    fingerprint_id=bytes.fromhex("0001e240"),
                    slot=3,
                    start_date=None,
                    end_date=None,
                )
            ]
        )
        client.weekly_schedules.set = AsyncMock()
        self._patch_client(cli_module, monkeypatch, client)
        arguments = [
            "set-schedule",
            "2",
            "--fingerprint",
            "0001e2400003",
            "--window",
            "mon=08:00-09:00",
            "-y",
        ]
        result = runner.invoke(cli_module.app, arguments)
        assert result.exit_code == 0, result.output
        client.weekly_schedules.set.assert_awaited_once()

    def test_set_schedule_aborts_without_confirmation(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.weekly_schedules.set = AsyncMock()
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(
            cli_module.app,
            ["set-schedule", "2", "--card", "00000001", "--window", "mon=08:00-09:00"],
            input="n\n",
        )
        assert result.exit_code != 0
        client.weekly_schedules.set.assert_not_awaited()

    def test_clear_schedule(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.weekly_schedules.clear = AsyncMock()
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(
            cli_module.app,
            ["clear-schedule", "2", "--fingerprint", "0001e2400003", "-v"],
            input="y\n",
        )
        assert result.exit_code == 0, result.output
        assert "fingerprint 0001e2400003" in result.output
        assert "weekly windows removed" in result.output
        client.weekly_schedules.clear.assert_awaited_once()

    def test_clear_schedule_skips_the_prompt_with_yes(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.weekly_schedules.clear = AsyncMock()
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["clear-schedule", "2", "--card", "00000001", "-y"])
        assert result.exit_code == 0, result.output
        client.weekly_schedules.clear.assert_awaited_once_with(Credential.card(1))

    def test_delete_passcode(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.passcodes.delete = AsyncMock()
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["delete-passcode", "2", "1234", "-v"])
        assert result.exit_code == 0, result.output
        assert "1234 removed" in result.output
        client.passcodes.delete.assert_awaited_once_with("1234")

    def test_clear_passcodes(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.clear_passcodes = AsyncMock()
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["clear-passcodes", "2", "--yes", "-v"])
        assert result.exit_code == 0, result.output
        assert "cleared" in result.output
        client.clear_passcodes.assert_awaited_once()

    def test_clear_passcodes_aborts_without_confirmation(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.clear_passcodes = AsyncMock()
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["clear-passcodes", "2"], input="n\n")
        assert result.exit_code != 0
        client.clear_passcodes.assert_not_awaited()

    def test_get_passcodes(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.get_passcodes = AsyncMock(
            return_value=[
                PasscodeEntry(
                    passcode="445566",
                    pwd_type=KeyboardPwdType.PERMANENT,
                    start_date=dt.datetime(2000, 1, 1, 0, 0),  # noqa: DTZ001 -- lock RTC is naive
                    end_date=None,
                    cyclic_schedule=None,
                ),
                PasscodeEntry(
                    passcode="11223344",
                    pwd_type=KeyboardPwdType.PERIOD,
                    start_date=dt.datetime(2025, 6, 1, 8, 0),  # noqa: DTZ001 -- lock RTC is naive
                    end_date=dt.datetime(2025, 12, 31, 20, 0),  # noqa: DTZ001 -- lock RTC is naive
                    cyclic_schedule=None,
                ),
                PasscodeEntry(
                    passcode="9988",
                    pwd_type=KeyboardPwdType.CIRCLE,
                    start_date=None,
                    end_date=None,
                    cyclic_schedule=CyclicSchedule(
                        day_or_preset="Monday", start_hour=8, start_minute=0, duration_hours=4
                    ),
                ),
            ]
        )
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["get-passcodes", "2", "-v"])
        assert result.exit_code == 0, result.output
        assert "passcode=445566" in result.output
        assert "type=permanent" in result.output
        assert "passcode=11223344" in result.output
        assert "type=custom" in result.output
        assert "2025-06-01 08:00:00" in result.output
        assert "2025-12-31 20:00:00" in result.output
        assert "passcode=9988" in result.output
        assert "type=cyclic" in result.output
        assert "Monday 08:00-12:00 (4h)" in result.output
        assert "not exhaustive" in result.output

    def test_get_passcodes_empty(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.get_passcodes = AsyncMock(return_value=[])
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["get-passcodes", "2"])
        assert result.exit_code == 0, result.output
        assert "no passcodes visible" in result.output

    def test_get_auto_lock(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.get_auto_lock_time = AsyncMock(return_value=45)
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["get-auto-lock", "2", "-v"])
        assert result.exit_code == 0, result.output
        assert "auto-lock: 45s" in result.output

    def test_get_auto_lock_unknown(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.get_auto_lock_time = AsyncMock(return_value=-1)
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["get-auto-lock", "2"])
        assert result.exit_code == 0, result.output
        assert "auto-lock: unknown" in result.output

    def test_set_auto_lock(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.set_auto_lock_time = AsyncMock()
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["set-auto-lock", "2", "45", "-v"])
        assert result.exit_code == 0, result.output
        assert "set to 45s" in result.output
        client.set_auto_lock_time.assert_awaited_once_with(45)

    def test_get_auto_lock_limits(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.get_auto_lock_limits = AsyncMock(
            return_value=AutoLockLimits(min_allowed=1, max_allowed=900)
        )
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["get-auto-lock-limits", "2", "-v"])
        assert result.exit_code == 0, result.output
        assert "min: 1s" in result.output
        assert "max: 900s" in result.output

    def test_get_fingerprints(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.get_fingerprints = AsyncMock(
            return_value=[
                FingerprintEntry(
                    fingerprint_id=bytes([0x00, 0x00, 0x00, 0x2A]),
                    slot=1,
                    start_date=dt.datetime(2026, 3, 1, 8, 0),  # noqa: DTZ001
                    end_date=None,
                ),
                FingerprintEntry(
                    fingerprint_id=bytes([0x00, 0x00, 0x00, 0x2B]),
                    slot=2,
                    start_date=None,
                    end_date=dt.datetime(2026, 12, 31, 23, 59),  # noqa: DTZ001
                ),
            ]
        )
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["get-fingerprints", "2", "-v"])
        assert result.exit_code == 0, result.output
        assert "id=0000002a0001" in result.output
        assert "end=permanent" in result.output
        assert "id=0000002b0002" in result.output
        assert "start=not set" in result.output
        assert "get-schedule" in result.output

    def test_get_fingerprints_empty(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.get_fingerprints = AsyncMock(return_value=[])
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["get-fingerprints", "2"])
        assert result.exit_code == 0, result.output
        assert "no fingerprints enrolled" in result.output

    def test_get_cards(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.get_cards = AsyncMock(
            return_value=[
                CardEntry(
                    card_id=bytes([0x11, 0x22, 0x33, 0x44]),
                    start_date=dt.datetime(2026, 3, 1, 8, 0),  # noqa: DTZ001
                    end_date=None,
                ),
                CardEntry(
                    card_id=bytes([0x11, 0x22, 0x33, 0x45]),
                    start_date=None,
                    end_date=dt.datetime(2026, 12, 31, 23, 59),  # noqa: DTZ001
                ),
            ]
        )
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["get-cards", "2", "-v"])
        assert result.exit_code == 0, result.output
        assert "id=11223344  number=287454020" in result.output
        assert "end=permanent" in result.output
        assert "id=11223345" in result.output
        assert "start=not set" in result.output
        assert "get-schedule" in result.output

    def test_get_cards_empty(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = MagicMock()
        client.get_cards = AsyncMock(return_value=[])
        self._patch_client(cli_module, monkeypatch, client)
        result = runner.invoke(cli_module.app, ["get-cards", "2"])
        assert result.exit_code == 0, result.output
        assert "no cards enrolled" in result.output
