"""Synthetic credential responses must not escape through SDK diagnostics."""

from __future__ import annotations

import logging
import traceback
from unittest.mock import AsyncMock

import pytest

from tests.conftest import make_virtual_key
from tests.test_client_ble import _resp_frame
from ttlock_ble import TTLockClient, TTLockError
from ttlock_ble import commands as cmd

_PIN = b"9081726"
_OLD_PIN = b"6172839"


def _response(*, pin=_PIN, trailer=b"\x00\x01\x01\x00\x00"):
    body = bytes([1, len(pin)]) + pin + bytes([len(_OLD_PIN)]) + _OLD_PIN + trailer
    return b"\x07\x01\x00\x00\x00\x00" + bytes([len(body)]) + body


def _assert_private(text, response):
    for secret in (_PIN, _OLD_PIN):
        assert secret.decode() not in text
        assert secret.hex() not in text
    assert response.hex() not in text


async def test_successful_read_retains_values_without_logging_credentials(caplog):
    key = make_virtual_key()
    client = TTLockClient(key)
    response = _response()
    client._admin_handshake = AsyncMock()
    client._transport.exchange = AsyncMock(
        return_value=_resp_frame(key, cmd.CMD_GET_PASSCODES, response)
    )
    with caplog.at_level(logging.DEBUG):
        entries = await client.get_passcodes()
    assert [entry.passcode for entry in entries] == [_PIN.decode()]
    assert entries[0].is_permanent
    _assert_private(caplog.text, response)


@pytest.mark.parametrize(
    ("response", "error_type"),
    [
        pytest.param(b"\x07\x00" + _PIN + _OLD_PIN, RuntimeError, id="rejected"),
        pytest.param(_response()[:-4], ValueError, id="truncated-trailer"),
        pytest.param(
            b"\x07\x01\x00\x00\x00\x00\x12\x01\xff" + _PIN + _OLD_PIN,
            ValueError,
            id="truncated-passcode",
        ),
        pytest.param(_response(trailer=b"\x00\xff\xff\x00\x00"), ValueError, id="date"),
        pytest.param(_response(pin=b"\xff" + _PIN), ValueError, id="non-ascii"),
    ],
)
async def test_parser_and_public_error_tracebacks_redact_credentials(response, error_type, caplog):
    with pytest.raises(error_type) as parsed:
        cmd.parse_passcode_list_response(response)
    _assert_private("".join(traceback.format_exception(parsed.value)), response)

    key = make_virtual_key()
    client = TTLockClient(key)
    client._admin_handshake = AsyncMock()
    client._transport.exchange = AsyncMock(
        return_value=_resp_frame(key, cmd.CMD_GET_PASSCODES, response)
    )
    with caplog.at_level(logging.DEBUG), pytest.raises(TTLockError) as public:
        await client.get_passcodes()
    _assert_private(caplog.text + "".join(traceback.format_exception(public.value)), response)
    assert "Failed to get_passcodes" in str(public.value)


@pytest.mark.parametrize("response", [b"", b"\x39"])
def test_short_envelope_uses_only_structural_diagnostics(response):
    with pytest.raises(ValueError) as error:
        cmd.parse_passcode_list_response(response)
    assert "response too short" in str(error.value)
    if response:
        assert response.hex() not in "".join(traceback.format_exception(error.value))
