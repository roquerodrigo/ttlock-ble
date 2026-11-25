"""Incomplete or inconsistent validity options are refused before the lock is contacted.

The card, passcode and fingerprint commands share their validity helpers, so
every refused combination is checked on each family. `Permanent` only comes
from `--permanent` (the modify commands) or from no validity options at all
(the enroll and add commands).
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from typer.testing import CliRunner

from tests.test_cli import _usage_error, _write_keys
from tests.test_cli_cards import _client
from ttlock_ble import Credential, Permanent

runner = CliRunner()
_CARD = "55667788"
_FINGERPRINT = "3299d6ae0000"

_ENROLL_AND_ADD = {
    "enroll-card": ["enroll-card", "2"],
    "add-card": ["add-card", "2", _CARD],
    "enroll-fingerprint": ["enroll-fingerprint", "2"],
    "add-passcode": ["add-passcode", "2", "1234"],
}
_MODIFY = {
    "modify-card": ["modify-card", "2", _CARD],
    "modify-fingerprint": ["modify-fingerprint", "2", _FINGERPRINT],
}
_COMMANDS = {**_ENROLL_AND_ADD, **_MODIFY}
_PASSCODE_ONLY = {"add-passcode": _COMMANDS["add-passcode"]}

_WINDOW_WITHOUT_DAYS = "--from and --to need --days"
_DAYS_WITHOUT_WINDOW = "--days needs --from and --to"
_UNPAIRED_DATES = "--start and --end go together"
_INCOMPLETE = [
    pytest.param(["--from", "08:00"], _WINDOW_WITHOUT_DAYS, id="from alone"),
    pytest.param(["--to", "09:00"], _WINDOW_WITHOUT_DAYS, id="to alone"),
    pytest.param(["--from", "08:00", "--to", "09:00"], _WINDOW_WITHOUT_DAYS, id="from and to"),
    pytest.param(
        ["--from", "08:00", "--start", "2026-12-24T18:00", "--end", "2026-12-26T12:00"],
        _WINDOW_WITHOUT_DAYS,
        id="from with dates",
    ),
    pytest.param(["--days", "mon"], _DAYS_WITHOUT_WINDOW, id="days alone"),
    pytest.param(["--days", "mon", "--from", "08:00"], _DAYS_WITHOUT_WINDOW, id="days and from"),
    pytest.param(["--days", "mon", "--to", "09:00"], _DAYS_WITHOUT_WINDOW, id="days and to"),
    pytest.param(["--start", "2026-12-24T18:00"], _UNPAIRED_DATES, id="start alone"),
    pytest.param(["--end", "2026-12-26T12:00"], _UNPAIRED_DATES, id="end alone"),
]
_WEEKLY = ["--days", "mon", "--from", "08:00", "--to", "09:00"]


@pytest.mark.parametrize("command", _COMMANDS)
@pytest.mark.parametrize(("options", "message"), _INCOMPLETE)
def test_incomplete_options_are_refused_before_connecting(
    cli_app, monkeypatch, command, options, message
) -> None:
    cli_module, store = cli_app
    _write_keys(store)
    client = _client(cli_module, monkeypatch)
    assert message in _usage_error(cli_module.app, [*_COMMANDS[command], *options])
    client.__aenter__.assert_not_called()


@pytest.mark.parametrize("command", [name for name in _COMMANDS if name != "add-passcode"])
@pytest.mark.parametrize(
    "options",
    [
        pytest.param([*_WEEKLY, "--start", "2026-12-24T18:00"], id="weekly with start alone"),
        pytest.param([*_WEEKLY, "--end", "2026-12-26T12:00"], id="weekly with end alone"),
    ],
)
def test_weekly_dates_must_come_in_pairs(cli_app, monkeypatch, command, options) -> None:
    cli_module, store = cli_app
    _write_keys(store)
    client = _client(cli_module, monkeypatch)
    assert _UNPAIRED_DATES in _usage_error(cli_module.app, [*_COMMANDS[command], *options])
    client.__aenter__.assert_not_called()


@pytest.mark.parametrize("command", _PASSCODE_ONLY)
@pytest.mark.parametrize(
    "options",
    [
        pytest.param(["--single-use"], id="alone"),
        pytest.param(["--single-use", "--start", "2026-12-24T18:00"], id="with start only"),
    ],
)
def test_single_use_needs_both_dates(cli_app, monkeypatch, command, options) -> None:
    cli_module, store = cli_app
    _write_keys(store)
    client = _client(cli_module, monkeypatch)
    message = _usage_error(cli_module.app, [*_COMMANDS[command], *options])
    assert ("--single-use needs --start and --end" in message) or (_UNPAIRED_DATES in message)
    client.__aenter__.assert_not_called()


@pytest.mark.parametrize("command", _MODIFY)
def test_a_modify_command_needs_permanent_or_a_change(cli_app, monkeypatch, command) -> None:
    cli_module, store = cli_app
    _write_keys(store)
    client = _client(cli_module, monkeypatch)
    assert "give --permanent" in _usage_error(cli_module.app, _COMMANDS[command])
    client.__aenter__.assert_not_called()


@pytest.mark.parametrize("command", _MODIFY)
def test_permanent_still_needs_to_be_asked_for_explicitly(cli_app, monkeypatch, command) -> None:
    cli_module, store = cli_app
    _write_keys(store)
    client = _client(cli_module, monkeypatch)
    family = client.cards if "card" in command else client.fingerprints
    family.modify = _awaitable()
    result = runner.invoke(cli_module.app, [*_COMMANDS[command], "--permanent"])
    assert result.exit_code == 0, result.output
    assert family.modify.await_args.args[1] == Permanent()


@pytest.mark.parametrize("command", _ENROLL_AND_ADD)
def test_no_options_at_all_is_still_permanent(cli_app, monkeypatch, command) -> None:
    cli_module, store = cli_app
    _write_keys(store)
    client = _client(cli_module, monkeypatch)
    for family, method in (
        (client.cards, "enroll"),
        (client.cards, "add"),
        (client.fingerprints, "enroll"),
        (client.passcodes, "add"),
    ):
        setattr(family, method, _awaitable(Credential.card(1)))
    result = runner.invoke(cli_module.app, _COMMANDS[command])
    assert result.exit_code == 0, result.output
    calls = {
        "enroll-card": client.cards.enroll,
        "add-card": client.cards.add,
        "enroll-fingerprint": client.fingerprints.enroll,
        "add-passcode": client.passcodes.add,
    }
    assert Permanent() in calls[command].await_args.args


def _awaitable(result=None) -> AsyncMock:
    return AsyncMock(return_value=result)
