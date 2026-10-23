"""Synthetic card-id responses must not escape through SDK diagnostics.

Mirrors `test_passcode_privacy.py`: a card id is a cloneable credential,
same as a keypad passcode, so `get_cards` and `parse_card_list_response`
get the same treatment - debug logs carry only structural facts (lengths,
status codes), and no raised error or its traceback echoes the raw bytes.
"""

from __future__ import annotations

import logging
import traceback
from unittest.mock import AsyncMock

import pytest

from tests.conftest import make_virtual_key
from tests.test_client_ble import _resp_frame
from ttlock_ble import TTLockClient, TTLockError
from ttlock_ble import commands as cmd

_CARD_ID = bytes([0xDE, 0xAD, 0xBE, 0xEF])


def _response(*, card_id: bytes = _CARD_ID, start: bytes = cmd.START_DATE_SENTINEL) -> bytes:
    data = bytes([0x64, 0x01, 0x00, 0x01]) + card_id + start + cmd.END_DATE_SENTINEL
    return bytes([cmd.CMD_MANAGE_IC_CARD, cmd.RESPONSE_SUCCESS]) + data


def _assert_private(text: str, response: bytes) -> None:
    assert _CARD_ID.hex() not in text
    assert response.hex() not in text


async def test_successful_read_retains_values_without_logging_credentials(caplog) -> None:
    key = make_virtual_key()
    client = TTLockClient(key)
    response = _response()
    end_of_list = bytes([cmd.CMD_MANAGE_IC_CARD, cmd.RESPONSE_SUCCESS, 0x64, 0x01, 0xFF, 0xFF])
    client._admin_handshake = AsyncMock()
    client._transport.exchange = AsyncMock(
        side_effect=[
            _resp_frame(key, cmd.CMD_MANAGE_IC_CARD, response),
            _resp_frame(key, cmd.CMD_MANAGE_IC_CARD, end_of_list),
        ]
    )
    with caplog.at_level(logging.DEBUG):
        entries = await client.get_cards()
    assert [entry.card_id for entry in entries] == [_CARD_ID]
    assert entries[0].is_permanent
    _assert_private(caplog.text, response)


@pytest.mark.parametrize(
    ("response", "error_type"),
    [
        pytest.param(
            bytes([cmd.CMD_MANAGE_IC_CARD, cmd.RESPONSE_FAILED, 0x02]) + _CARD_ID,
            RuntimeError,
            id="rejected",
        ),
        pytest.param(_response()[:-1], ValueError, id="truncated"),
        pytest.param(_response() + b"\x00", ValueError, id="overlong"),
    ],
)
async def test_parser_and_public_error_tracebacks_redact_credentials(
    response: bytes, error_type: type[Exception], caplog
) -> None:
    with pytest.raises(error_type) as parsed:
        cmd.parse_card_list_response(response)
    _assert_private("".join(traceback.format_exception(parsed.value)), response)

    key = make_virtual_key()
    client = TTLockClient(key)
    client._admin_handshake = AsyncMock()
    client._transport.exchange = AsyncMock(
        return_value=_resp_frame(key, cmd.CMD_MANAGE_IC_CARD, response)
    )
    with caplog.at_level(logging.DEBUG), pytest.raises(TTLockError) as public:
        await client.get_cards()
    _assert_private(caplog.text + "".join(traceback.format_exception(public.value)), response)
    assert "Failed to get_cards" in str(public.value)
