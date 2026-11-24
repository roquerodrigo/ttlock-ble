"""The card commands of the CLI: enroll, add, modify, delete and clear."""

from __future__ import annotations

import datetime as dt
from unittest.mock import AsyncMock, MagicMock

import pytest
from typer.testing import CliRunner

from tests.test_cli import _usage_error, _write_keys
from ttlock_ble import (
    CardEnrollmentStep,
    CardPresentedLateError,
    Credential,
    CredentialNotFoundError,
    EnrollmentTimeoutError,
    LockFeature,
    Period,
    Permanent,
    StorageFullError,
    TTLockError,
    UnsupportedFeatureError,
    Weekday,
    Weekly,
    WeeklyWindow,
)
from ttlock_ble.credentials.card_manager import ENROLL_SAFETY_WINDOW

runner = CliRunner()
_NUMBER = 0x55667788
_START = dt.datetime(2026, 12, 24, 18)  # noqa: DTZ001 -- lock-local wall clock
_END = dt.datetime(2026, 12, 26, 12)  # noqa: DTZ001 -- lock-local wall clock
_WEEKDAYS_9_TO_5 = Weekly(
    tuple(WeeklyWindow(day, dt.time(9), dt.time(17)) for day in Weekday if day < Weekday.SATURDAY)
)
_VALIDITY_OPTIONS = [
    pytest.param([], Permanent(), id="permanent"),
    pytest.param(
        ["--start", "2026-12-24T18:00", "--end", "2026-12-26T12:00"],
        Period(_START, _END),
        id="period",
    ),
    pytest.param(
        ["--days", "workdays", "--from", "09:00", "--to", "17:00"],
        _WEEKDAYS_9_TO_5,
        id="weekly",
    ),
    pytest.param(
        [
            *["--days", "workdays", "--from", "09:00", "--to", "17:00"],
            *["--start", "2026-12-24T18:00", "--end", "2026-12-26T12:00"],
        ],
        Weekly(_WEEKDAYS_9_TO_5.windows, _START, _END),
        id="weekly with dates",
    ),
]


def _client(cli_module, monkeypatch) -> MagicMock:
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    monkeypatch.setattr(cli_module, "TTLockClient", lambda _key: client)
    return client


class TestEnrollCard:
    @pytest.mark.parametrize(("options", "validity"), _VALIDITY_OPTIONS)
    def test_enrolls_with_each_validity(self, cli_app, monkeypatch, options, validity) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)

        async def enroll(given, on_progress, **options) -> Credential:
            assert (given, options) == (validity, {"timeout": 30.0})
            on_progress(CardEnrollmentStep.WAITING_FOR_CARD)
            on_progress(CardEnrollmentStep.CARD_READ)
            return Credential.card(_NUMBER)

        client.cards.enroll = AsyncMock(side_effect=enroll)
        result = runner.invoke(cli_module.app, ["enroll-card", "2", *options, "-v"])
        assert result.exit_code == 0, result.output
        assert "Present the card to the lock now" in result.output
        assert f"number {_NUMBER}" in result.output
        assert "id 55667788" in result.output

    def test_a_longer_wait(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        client.cards.enroll = AsyncMock(return_value=Credential.card(_NUMBER))
        result = runner.invoke(cli_module.app, ["enroll-card", "2", "--timeout", "60"])
        assert result.exit_code == 0, result.output
        assert client.cards.enroll.await_args.kwargs == {"timeout": 60.0}

    def test_the_default_wait_covers_the_locks_add_mode(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        client.cards.enroll = AsyncMock(return_value=Credential.card(_NUMBER))
        runner.invoke(cli_module.app, ["enroll-card", "2"])
        assert client.cards.enroll.await_args.kwargs["timeout"] >= ENROLL_SAFETY_WINDOW

    @pytest.mark.parametrize(
        ("error", "text"),
        [
            (EnrollmentTimeoutError("Failed to enroll_card: no card"), "no card"),
            (
                CardPresentedLateError("Failed to enroll_card: late, removed", removed=True),
                "late, removed",
            ),
            (CredentialNotFoundError("delete_card", 0x18), "delete_card"),
            (StorageFullError("add_card", 0x16), "add_card"),
            (UnsupportedFeatureError("add_card", LockFeature.IC), "IC"),
            (TTLockError("Failed to do it: boom"), "boom"),
        ],
        ids=["timeout", "late card", "not found", "full", "unsupported", "other"],
    )
    @pytest.mark.parametrize(
        "arguments",
        [
            ["enroll-card", "2"],
            ["add-card", "2", "5"],
            ["modify-card", "2", "5", "--permanent"],
            ["delete-card", "2", "5", "-y"],
            ["clear-cards", "2", "-y"],
        ],
    )
    def test_library_errors_become_one_error_line(
        self, cli_app, monkeypatch, arguments, error, text
    ) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        for method in ("enroll", "add", "modify", "delete", "clear"):
            setattr(client.cards, method, AsyncMock(side_effect=error))
        result = runner.invoke(cli_module.app, arguments)
        assert result.exit_code == 1
        assert result.output.strip() == f"error: {error}"
        assert text in result.output
        assert "Traceback" not in result.output
        assert result.exception is None or isinstance(result.exception, SystemExit)

    @pytest.mark.parametrize(
        ("options", "message"),
        [
            (["--start", "2026-12-24T18:00"], "--start and --end go together"),
            (["--days", "mon"], "--from"),
            (["--days", "mon", "--from", "18:00", "--to", "09:00"], "start before it ends"),
            (
                ["--days", "mon", "--from", "09:00", "--to", "17:00", "--start", "2026-12-24"],
                "go together",
            ),
            (["--end", "tomorrow", "--start", "2026-12-24T18:00"], "--end must look like"),
            (["--start", "2026-12-26T12:00", "--end", "2026-12-24T18:00"], "start before it ends"),
        ],
    )
    def test_bad_validity_never_connects(self, cli_app, monkeypatch, options, message) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        assert message in _usage_error(cli_module.app, ["enroll-card", "2", *options])
        client.__aenter__.assert_not_called()


class TestAddCard:
    @pytest.mark.parametrize(("options", "validity"), _VALIDITY_OPTIONS)
    def test_adds_with_each_validity(self, cli_app, monkeypatch, options, validity) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        client.cards.add = AsyncMock()
        result = runner.invoke(cli_module.app, ["add-card", "2", str(_NUMBER), *options, "-v"])
        assert result.exit_code == 0, result.output
        assert f"card {_NUMBER} added" in result.output
        client.cards.add.assert_awaited_once_with(Credential.card(_NUMBER), validity)

    @pytest.mark.parametrize(
        "arguments",
        [
            ["add-card", "2", "12abc"],
            ["add-card", "2", str(1 << 64)],
            ["add-card", "2", "5", "--start", "2026-12-24T18:00"],
        ],
    )
    def test_bad_input_never_connects(self, cli_app, monkeypatch, arguments) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        _usage_error(cli_module.app, arguments)
        client.__aenter__.assert_not_called()


class TestModifyCard:
    @pytest.mark.parametrize(
        ("options", "validity"), [param for param in _VALIDITY_OPTIONS if param.values[0]]
    )
    def test_modifies_with_a_new_validity(self, cli_app, monkeypatch, options, validity) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        client.cards.modify = AsyncMock()
        result = runner.invoke(cli_module.app, ["modify-card", "2", str(_NUMBER), *options, "-v"])
        assert result.exit_code == 0, result.output
        assert f"card {_NUMBER} updated" in result.output
        client.cards.modify.assert_awaited_once_with(Credential.card(_NUMBER), validity)

    def test_permanent_must_be_asked_for(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        client.cards.modify = AsyncMock()
        result = runner.invoke(cli_module.app, ["modify-card", "2", str(_NUMBER), "--permanent"])
        assert result.exit_code == 0, result.output
        client.cards.modify.assert_awaited_once_with(Credential.card(_NUMBER), Permanent())

    @pytest.mark.parametrize(
        "options",
        [[], ["--permanent", "--start", "2026-12-24T18:00", "--end", "2026-12-26T12:00"]],
        ids=["nothing", "both"],
    )
    def test_needs_exactly_one_kind_of_change(self, cli_app, monkeypatch, options) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        assert "give --permanent" in _usage_error(
            cli_module.app, ["modify-card", "2", str(_NUMBER), *options]
        )
        client.__aenter__.assert_not_called()


class TestDeleteCard:
    def test_asks_first(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        client.cards.delete = AsyncMock()
        result = runner.invoke(cli_module.app, ["delete-card", "2", str(_NUMBER)], input="y\n")
        assert result.exit_code == 0, result.output
        assert f"Remove card {_NUMBER}" in result.output
        client.cards.delete.assert_awaited_once_with(Credential.card(_NUMBER))

    def test_aborts_without_confirmation(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        client.cards.delete = AsyncMock()
        result = runner.invoke(cli_module.app, ["delete-card", "2", str(_NUMBER)], input="n\n")
        assert result.exit_code != 0
        client.cards.delete.assert_not_awaited()

    @pytest.mark.parametrize("flag", ["--yes", "-y"])
    def test_yes_skips_the_question(self, cli_app, monkeypatch, flag) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        client.cards.delete = AsyncMock()
        result = runner.invoke(cli_module.app, ["delete-card", "2", str(_NUMBER), flag, "-v"])
        assert result.exit_code == 0, result.output
        assert "Remove card" not in result.output
        assert f"card {_NUMBER} removed" in result.output
        client.cards.delete.assert_awaited_once_with(Credential.card(_NUMBER))

    def test_a_bad_number_never_asks_or_connects(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        assert "8 bytes" in _usage_error(cli_module.app, ["delete-card", "2", str(1 << 64), "-y"])
        client.__aenter__.assert_not_called()


class TestClearCards:
    def test_says_it_removes_every_card_and_asks(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        client.cards.clear = AsyncMock()
        result = runner.invoke(cli_module.app, ["clear-cards", "2"], input="y\n")
        assert result.exit_code == 0, result.output
        assert "removes EVERY card" in result.output
        client.cards.clear.assert_awaited_once()

    def test_aborts_without_confirmation(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        client.cards.clear = AsyncMock()
        result = runner.invoke(cli_module.app, ["clear-cards", "2"], input="n\n")
        assert result.exit_code != 0
        client.cards.clear.assert_not_awaited()

    @pytest.mark.parametrize("flag", ["--yes", "-y"])
    def test_yes_skips_the_question(self, cli_app, monkeypatch, flag) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        client.cards.clear = AsyncMock()
        result = runner.invoke(cli_module.app, ["clear-cards", "2", flag, "-v"])
        assert result.exit_code == 0, result.output
        assert "removes EVERY card" not in result.output
        assert "all cards cleared" in result.output
        client.cards.clear.assert_awaited_once()


def test_the_help_of_clear_says_it_removes_every_card(cli_app) -> None:
    cli_module, _store = cli_app
    help_text = runner.invoke(cli_module.app, ["clear-cards", "--help"], env={"COLUMNS": "300"})
    assert "EVERY card" in help_text.output
