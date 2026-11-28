"""Every CLI command that talks to a lock prints a library error as one line."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from typer.testing import CliRunner

from tests.test_cli import _write_keys
from ttlock_ble import LockRejectedError, ReplyTimeoutError, StorageFullError, TTLockError

runner = CliRunner()


def _client(cli_module, monkeypatch) -> MagicMock:
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    monkeypatch.setattr(cli_module, "TTLockClient", lambda _key: client)
    return client


# (command line, dotted client method that raises, error)
_REFUSALS = [
    pytest.param(["unlock", "2"], "unlock", LockRejectedError("unlock", 0x01), id="unlock"),
    pytest.param(["state", "2"], "query_state", ReplyTimeoutError("query_state"), id="state"),
    pytest.param(["sound", "2", "on"], "set_lock_sound", TTLockError("boom"), id="sound"),
    pytest.param(
        ["features", "2"], "get_device_features", TTLockError("Failed to get: x"), id="features"
    ),
    pytest.param(
        ["add-passcode", "2", "123456"],
        "passcodes.add",
        StorageFullError("add_passcode", 0x16),
        id="passcodes",
    ),
    pytest.param(
        ["get-passcodes", "2"],
        "get_passcodes",
        LockRejectedError("get_passcodes", 0x18),
        id="get-passcodes",
    ),
    pytest.param(
        ["get-admin-passcode", "2"],
        "admin_passcode.get",
        LockRejectedError("get_admin_passcode", 0x18),
        id="admin passcode",
    ),
    pytest.param(
        ["set-admin-passcode", "2", "123456", "-y"],
        "admin_passcode.set",
        LockRejectedError("set_admin_passcode", 0x18),
        id="set admin passcode",
    ),
    pytest.param(
        ["get-schedule", "2", "--card", "55667788"],
        "weekly_schedules.get",
        LockRejectedError("get_schedule", 0x18),
        id="schedule",
    ),
    pytest.param(
        ["get-auto-lock", "2"],
        "get_auto_lock_time",
        LockRejectedError("auto", 0x18),
        id="auto-lock",
    ),
    pytest.param(
        ["get-fingerprints", "2"],
        "get_fingerprints",
        LockRejectedError("get_fingerprints", 0x18),
        id="get-fingerprints",
    ),
    pytest.param(
        ["get-cards", "2"], "get_cards", LockRejectedError("get_cards", 0x18), id="get-cards"
    ),
]


class TestLockErrorsAreOneLine:
    @pytest.mark.parametrize(("arguments", "method", "error"), _REFUSALS)
    def test_typed_errors_print_one_line(
        self, cli_app, monkeypatch, arguments, method, error
    ) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        target = client
        *path, name = method.split(".")
        for part in path:
            target = getattr(target, part)
        setattr(target, name, AsyncMock(side_effect=error))
        result = runner.invoke(cli_module.app, arguments)
        assert result.exit_code == 1
        assert result.output.strip() == f"error: {error}"
        assert "Traceback" not in result.output
        assert result.exception is None or isinstance(result.exception, SystemExit)

    def test_other_errors_keep_their_traceback(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        client.unlock = AsyncMock(side_effect=RuntimeError("bug"))
        result = runner.invoke(cli_module.app, ["unlock", "2"])
        assert result.exit_code == 1
        assert isinstance(result.exception, RuntimeError)
        assert "error: bug" not in result.output
