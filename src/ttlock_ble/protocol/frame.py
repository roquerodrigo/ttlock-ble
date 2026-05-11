"""Frame: serialise and parse a single TTLock V3 (or legacy) BLE packet."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..crypto import aes_decrypt, aes_encrypt, crc_compute
from .constants import ENCRYPT_AES, ENCRYPT_PLAIN, HEADER, TRAILER

if TYPE_CHECKING:
    from ..models import LockVersion


@dataclass(slots=True)
class Frame:
    """A TTLock command frame.

    Wire layout (V3+, `protocol_type >= 5`):

        7F 5A | proto | sub_ver | scene | group_id(2) | sub_org(2) |
        cmd | encrypt | length | data[length] | CRC | 0D 0A

    The TTLock firmware uses CRLF (0D 0A) as a frame terminator on the
    GATT characteristic — without it the lock buffers our writes and
    never invokes its protocol handler.
    """

    protocol_type: int
    sub_version: int
    scene: int
    group_id: int
    sub_org: int
    command: int
    encrypt: int
    data: bytes

    def build(self) -> bytes:
        """Serialise to the wire bytes a BLE write expects (CRLF-terminated)."""
        if self.protocol_type >= 5:
            body = (
                bytes(
                    [
                        HEADER[0],
                        HEADER[1],
                        self.protocol_type & 0xFF,
                        self.sub_version & 0xFF,
                        self.scene & 0xFF,
                        (self.group_id >> 8) & 0xFF,
                        self.group_id & 0xFF,
                        (self.sub_org >> 8) & 0xFF,
                        self.sub_org & 0xFF,
                        self.command & 0xFF,
                        self.encrypt & 0xFF,
                        len(self.data) & 0xFF,
                    ]
                )
                + self.data
            )
        else:
            body = (
                bytes(
                    [
                        HEADER[0],
                        HEADER[1],
                        self.protocol_type & 0xFF,
                        self.command & 0xFF,
                        self.encrypt & 0xFF,
                        len(self.data) & 0xFF,
                    ]
                )
                + self.data
            )
        return body + bytes([crc_compute(body)]) + TRAILER

    @classmethod
    def for_lock(
        cls,
        lock_version: LockVersion,
        command: int,
        data: bytes,
        encrypt: int = ENCRYPT_PLAIN,
    ) -> Frame:
        """Construct a fresh outgoing frame addressed to a specific lock."""
        return cls(
            protocol_type=lock_version.protocolType,
            sub_version=lock_version.protocolVersion,
            scene=lock_version.scene,
            group_id=lock_version.groupId,
            sub_org=lock_version.orgId,
            command=command,
            encrypt=encrypt,
            data=data,
        )

    def encrypt_data(self, key: bytes) -> Frame:
        """Return a copy with the payload AES-encrypted under `key`.

        The `encrypt` byte stays at 0xAA (APP_COMMAND) — the firmware uses
        this as a literal "frame from the app" marker. The SDK's
        ENCRY_AES_CBC=0x02 constant is never sent on the wire by the
        official client; we mirror that.
        """
        return Frame(
            self.protocol_type,
            self.sub_version,
            self.scene,
            self.group_id,
            self.sub_org,
            self.command,
            ENCRYPT_PLAIN,
            aes_encrypt(self.data, key),
        )

    @classmethod
    def parse(cls, raw: bytes) -> Frame:
        """Parse a raw frame body (without CRC trailer) into a `Frame`."""
        if len(raw) < 7 or raw[0] != HEADER[0] or raw[1] != HEADER[1]:
            raise ValueError(f"Invalid TTLock frame: {raw.hex()}")
        proto = raw[2]
        if proto >= 5:
            sub_version = raw[3]
            scene = raw[4]
            group_id = (raw[5] << 8) | raw[6]
            sub_org = (raw[7] << 8) | raw[8]
            command = raw[9]
            encrypt = raw[10]
            length = raw[11]
            data = raw[12 : 12 + length]
        else:
            sub_version = 0
            scene = 0
            group_id = 0
            sub_org = 0
            command = raw[3]
            encrypt = raw[4]
            length = raw[5]
            data = raw[6 : 6 + length]
        return cls(proto, sub_version, scene, group_id, sub_org, command, encrypt, data)

    def decrypt_data(self, key: bytes) -> bytes:
        """Decrypt the payload under `key` (no-op when payload is plaintext)."""
        if self.encrypt != ENCRYPT_AES:
            return self.data
        return aes_decrypt(self.data, key)
