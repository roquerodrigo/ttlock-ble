"""The lock's feature value - CMD 0x01 (`COMM_SEARCHE_DEVICE_FEATURE` in the official SDK).

Empty request body; the response carries the capability bits the lock
advertises. The layout follows the SDK's response parser and its
`convertToFeatureValue` helper, not a hardware capture:

    [0]     battery percentage
    [1:5]   feature word 0 (big-endian) - bits 0-31, what the cloud calls
            `specialValue`
    [5:9]   feature word 1 - bits 32-63
    ...     one more word per 32 bits the firmware defines

Words arrive least-significant first; the SDK stitches them into one hex
string by prepending each new word, and drops a trailing partial word, so
the parser does the same.
"""

from __future__ import annotations

from ..models import DeviceFeatures
from .envelope import RESPONSE_SUCCESS, parse_response_status

_WORD_LENGTH = 4
_MINIMUM_DATA_LENGTH = 1 + _WORD_LENGTH


def payload_search_device_feature() -> bytes:
    """COMM_SEARCHE_DEVICE_FEATURE - empty request body; the lock replies with its feature value."""
    return b""


def parse_device_feature_response(plaintext: bytes) -> DeviceFeatures:
    """Decode the feature words into a `DeviceFeatures`.

    Raises `RuntimeError` on a FAILED status and `ValueError` when a
    SUCCESS response is too short to carry the battery byte and at least
    one complete feature word.
    """
    _cmd_echo, status, data = parse_response_status(plaintext)
    if status != RESPONSE_SUCCESS:
        raise RuntimeError(f"searchDeviceFeature FAILED: status={status:#x} err={data.hex()}")
    if len(data) < _MINIMUM_DATA_LENGTH:
        raise ValueError(f"searchDeviceFeature payload too short: {plaintext.hex()}")
    words = data[1:]
    complete_words = len(words) // _WORD_LENGTH
    mask = 0
    for index in range(complete_words):
        word = words[index * _WORD_LENGTH : (index + 1) * _WORD_LENGTH]
        mask |= int.from_bytes(word, "big") << (32 * index)
    return DeviceFeatures(mask=mask, battery=data[0])
