"""The fingerprint commands of the CLI: enroll, modify, delete and clear."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from typer.testing import CliRunner

from tests.test_cli import _usage_error, _write_keys
from tests.test_cli_cards import _VALIDITY_OPTIONS, _client
from ttlock_ble import (
    Credential,
    CredentialNotFoundError,
    EnrollmentTimeoutError,
    FingerprintEnrolledLateError,
    FingerprintEnrollmentProgress,
    FingerprintEnrollmentStep,
    LockFeature,
    Permanent,
    StorageFullError,
    TTLockError,
    UnsupportedFeatureError,
)
from ttlock_ble.credentials.fingerprint_manager import DEFAULT_ENROLL_TIMEOUT, LOCK_REPLY_TIMEOUT

runner = CliRunner()
_ID = "3299d6ae0000"
_FINGERPRINT = Credential.fingerprint(bytes.fromhex(_ID))


def _progress(step: FingerprintEnrollmentStep, recorded: int) -> FingerprintEnrollmentProgress:
    return FingerprintEnrollmentProgress(step, recorded, 4)


class TestEnrollFingerprint:
    @pytest.mark.parametrize(("options", "validity"), _VALIDITY_OPTIONS)
    def test_enrolls_with_each_validity(self, cli_app, monkeypatch, options, validity) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)

        async def enroll(given, on_progress, **options) -> Credential:
            assert (given, options) == (validity, {"timeout": DEFAULT_ENROLL_TIMEOUT})
            on_progress(_progress(FingerprintEnrollmentStep.WAITING_FOR_FINGER, 0))
            for touch in (1, 2, 3):
                on_progress(_progress(FingerprintEnrollmentStep.TOUCH_RECORDED, touch))
            on_progress(_progress(FingerprintEnrollmentStep.FINGERPRINT_READ, 4))
            return _FINGERPRINT

        client.fingerprints.enroll = AsyncMock(side_effect=enroll)
        result = runner.invoke(cli_module.app, ["enroll-fingerprint", "2", *options, "-v"])
        assert result.exit_code == 0, result.output
        assert "Touch the lock's sensor" in result.output
        assert "4 touches are needed" in result.output
        for touch in (1, 2, 3):
            assert f"touch {touch}/4" in result.output
        assert "touch 4/4" not in result.output
        assert f"✓ fingerprint enrolled: id {_ID}" in result.output

    def test_a_longer_wait(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        client.fingerprints.enroll = AsyncMock(return_value=_FINGERPRINT)
        result = runner.invoke(cli_module.app, ["enroll-fingerprint", "2", "--timeout", "60"])
        assert result.exit_code == 0, result.output
        assert client.fingerprints.enroll.await_args.kwargs == {"timeout": 60.0}

    def test_the_default_deadline_leaves_time_for_four_touches(self) -> None:
        assert DEFAULT_ENROLL_TIMEOUT >= 3 * 8.4

    def test_the_reply_timeout_outlasts_the_locks_own_timeout(self) -> None:
        assert LOCK_REPLY_TIMEOUT >= 15

    def test_the_help_warns_about_a_finger_that_is_already_enrolled(self, cli_app) -> None:
        cli_module, _store = cli_app
        result = runner.invoke(
            cli_module.app, ["enroll-fingerprint", "--help"], env={"COLUMNS": "300"}
        )
        assert "already enrolled" in " ".join(result.output.split())

    @pytest.mark.parametrize(
        "options",
        [
            ["--start", "2026-12-24T18:00"],
            ["--days", "mon"],
            ["--start", "2026-12-26T12:00", "--end", "2026-12-24T18:00"],
        ],
    )
    def test_bad_validity_never_connects(self, cli_app, monkeypatch, options) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        _usage_error(cli_module.app, ["enroll-fingerprint", "2", *options])
        client.__aenter__.assert_not_called()


@pytest.mark.parametrize(
    ("error", "text"),
    [
        (EnrollmentTimeoutError("Failed to enroll_fingerprint: not placed"), "not placed"),
        (
            FingerprintEnrolledLateError(
                "Failed to enroll_fingerprint: late, removed", removed=True
            ),
            "late, removed",
        ),
        (CredentialNotFoundError("delete_fingerprint", 0x1A), "delete_fingerprint"),
        (StorageFullError("enroll_fingerprint", 0x16), "enroll_fingerprint"),
        (UnsupportedFeatureError("enroll_fingerprint", LockFeature.FINGER_PRINT), "FINGER_PRINT"),
        (TTLockError("Failed to do it: boom"), "boom"),
    ],
    ids=["timeout", "late finger", "not found", "full", "unsupported", "other"],
)
@pytest.mark.parametrize(
    "arguments",
    [
        ["enroll-fingerprint", "2"],
        ["modify-fingerprint", "2", _ID, "--permanent"],
        ["delete-fingerprint", "2", _ID, "-y"],
        ["clear-fingerprints", "2", "-y"],
    ],
)
def test_library_errors_become_one_error_line(cli_app, monkeypatch, arguments, error, text) -> None:
    cli_module, store = cli_app
    _write_keys(store)
    client = _client(cli_module, monkeypatch)
    for method in ("enroll", "modify", "delete", "clear"):
        setattr(client.fingerprints, method, AsyncMock(side_effect=error))
    result = runner.invoke(cli_module.app, arguments)
    assert result.exit_code == 1
    assert result.output.strip() == f"error: {error}"
    assert text in result.output
    assert "Traceback" not in result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)


class TestModifyFingerprint:
    @pytest.mark.parametrize(
        ("options", "validity"), [param for param in _VALIDITY_OPTIONS if param.values[0]]
    )
    def test_modifies_with_a_new_validity(self, cli_app, monkeypatch, options, validity) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        client.fingerprints.modify = AsyncMock()
        result = runner.invoke(cli_module.app, ["modify-fingerprint", "2", _ID, *options, "-v"])
        assert result.exit_code == 0, result.output
        assert f"fingerprint {_ID} updated" in result.output
        client.fingerprints.modify.assert_awaited_once_with(_FINGERPRINT, validity)

    def test_permanent_must_be_asked_for(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        client.fingerprints.modify = AsyncMock()
        result = runner.invoke(cli_module.app, ["modify-fingerprint", "2", _ID, "--permanent"])
        assert result.exit_code == 0, result.output
        client.fingerprints.modify.assert_awaited_once_with(_FINGERPRINT, Permanent())

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
            cli_module.app, ["modify-fingerprint", "2", _ID, *options]
        )
        client.__aenter__.assert_not_called()

    @pytest.mark.parametrize("fingerprint_id", ["12abc", "0102030405", "3299d6ae"])
    def test_a_bad_id_never_connects(self, cli_app, monkeypatch, fingerprint_id) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        _usage_error(cli_module.app, ["modify-fingerprint", "2", fingerprint_id, "--permanent"])
        client.__aenter__.assert_not_called()


class TestDeleteFingerprint:
    def test_asks_first(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        client.fingerprints.delete = AsyncMock()
        result = runner.invoke(cli_module.app, ["delete-fingerprint", "2", _ID], input="y\n")
        assert result.exit_code == 0, result.output
        assert f"Remove fingerprint {_ID}" in result.output
        client.fingerprints.delete.assert_awaited_once_with(_FINGERPRINT)

    def test_aborts_without_confirmation(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        client.fingerprints.delete = AsyncMock()
        result = runner.invoke(cli_module.app, ["delete-fingerprint", "2", _ID], input="n\n")
        assert result.exit_code != 0
        client.fingerprints.delete.assert_not_awaited()

    @pytest.mark.parametrize("flag", ["--yes", "-y"])
    def test_yes_skips_the_question(self, cli_app, monkeypatch, flag) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        client.fingerprints.delete = AsyncMock()
        result = runner.invoke(cli_module.app, ["delete-fingerprint", "2", _ID, flag, "-v"])
        assert result.exit_code == 0, result.output
        assert "Remove fingerprint" not in result.output
        assert f"fingerprint {_ID} removed" in result.output
        client.fingerprints.delete.assert_awaited_once_with(_FINGERPRINT)

    def test_a_bad_id_never_asks_or_connects(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        message = _usage_error(cli_module.app, ["delete-fingerprint", "2", "0102", "-y"])
        assert "fingerprint id must be 6 bytes" in message
        client.__aenter__.assert_not_called()


class TestClearFingerprints:
    def test_says_it_removes_every_fingerprint_and_asks(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        client.fingerprints.clear = AsyncMock()
        result = runner.invoke(cli_module.app, ["clear-fingerprints", "2"], input="y\n")
        assert result.exit_code == 0, result.output
        assert "removes EVERY fingerprint" in result.output
        client.fingerprints.clear.assert_awaited_once()

    def test_aborts_without_confirmation(self, cli_app, monkeypatch) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        client.fingerprints.clear = AsyncMock()
        result = runner.invoke(cli_module.app, ["clear-fingerprints", "2"], input="n\n")
        assert result.exit_code != 0
        client.fingerprints.clear.assert_not_awaited()

    @pytest.mark.parametrize("flag", ["--yes", "-y"])
    def test_yes_skips_the_question(self, cli_app, monkeypatch, flag) -> None:
        cli_module, store = cli_app
        _write_keys(store)
        client = _client(cli_module, monkeypatch)
        client.fingerprints.clear = AsyncMock()
        result = runner.invoke(cli_module.app, ["clear-fingerprints", "2", flag, "-v"])
        assert result.exit_code == 0, result.output
        assert "removes EVERY fingerprint" not in result.output
        assert "all fingerprints cleared" in result.output
        client.fingerprints.clear.assert_awaited_once()


def test_the_help_of_clear_says_it_removes_every_fingerprint(cli_app) -> None:
    cli_module, _store = cli_app
    result = runner.invoke(cli_module.app, ["clear-fingerprints", "--help"], env={"COLUMNS": "300"})
    assert "EVERY fingerprint" in result.output
