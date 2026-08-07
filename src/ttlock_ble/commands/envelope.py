"""The `[cmd_echo][status][data...]` wrapper every lock response carries."""

from __future__ import annotations

from ..constants import ResponseStatus

RESPONSE_SUCCESS = ResponseStatus.SUCCESS
RESPONSE_FAILED = ResponseStatus.FAILED


def parse_response_status(plaintext: bytes) -> tuple[int, int, bytes]:
    """Decode the universal `[cmd_echo][status][data...]` response wrapper.

    Returns `(cmd_echo, status, data)`. `status == RESPONSE_SUCCESS (1)`
    means OK; `RESPONSE_FAILED (0)` carries an error code in `data[0]`.
    """
    if len(plaintext) < 2:
        raise ValueError(f"response too short: {plaintext.hex()}")
    return plaintext[0], plaintext[1], plaintext[2:]
