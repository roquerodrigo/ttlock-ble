"""TTLockClient construction and event-listener routing (no BLE I/O)."""

from unittest.mock import MagicMock

from ttlock_ble import LockEvent, LockVersion, TTLockClient, VirtualKey
from ttlock_ble.crypto import aes_encrypt, hex_key_to_bytes
from ttlock_ble.protocol import Frame


def _virtual_key() -> VirtualKey:
    return VirtualKey(
        keyId=1,
        lockId=2,
        lockMac="E9:EF:A0:BD:22:1D",
        lockAlias="Apto. 2616",
        lockName="DLock-XP",
        lockVersion=LockVersion(
            protocolType=5,
            protocolVersion=3,
            scene=2,
            groupId=1,
            orgId=1,
        ),
        aesKeyStr="2c,3d,23,5a,12,9c,74,0a,89,d5,0c,24,a5,3b,83,66",
        unlockKey="375773543",
        lockFlagPos=0,
        timezoneRawOffSet=-10800000,
        userType="110301",
        adminPs="422531259",
    )


class TestConstruction:
    def test_defaults_no_device(self):
        client = TTLockClient(_virtual_key())
        assert client.is_connected is False
        assert client._device is None

    def test_from_ble_device_attaches_device(self):
        device = MagicMock(name="BLEDevice")
        client = TTLockClient.from_ble_device(device, _virtual_key())
        assert client._device is device

    def test_disconnected_callback_stored(self):
        cb = MagicMock(name="disconnected_callback")
        client = TTLockClient.from_ble_device(MagicMock(), _virtual_key(), disconnected_callback=cb)
        assert client._disconnected_callback is cb


class TestEventListeners:
    def test_add_remove(self):
        client = TTLockClient(_virtual_key())
        cb = MagicMock(name="event_listener")
        client.add_event_listener(cb)
        assert cb in client._event_listeners
        client.remove_event_listener(cb)
        assert cb not in client._event_listeners

    def test_remove_unregistered_is_noop(self):
        client = TTLockClient(_virtual_key())
        client.remove_event_listener(MagicMock())  # must not raise

    def test_dedup(self):
        client = TTLockClient(_virtual_key())
        cb = MagicMock()
        client.add_event_listener(cb)
        client.add_event_listener(cb)
        assert client._event_listeners.count(cb) == 1


class TestPushDispatch:
    """Frames received outside an _exchange must surface as LockEvents."""

    def _build_push_frame(self, key: VirtualKey, plaintext: bytes) -> Frame:
        aes = hex_key_to_bytes(key.aesKeyStr)
        encrypted = aes_encrypt(plaintext, aes)
        return Frame(
            protocol_type=key.lockVersion.protocolType,
            sub_version=key.lockVersion.protocolVersion,
            scene=key.lockVersion.scene,
            group_id=key.lockVersion.groupId,
            sub_org=key.lockVersion.orgId,
            command=0x54,
            encrypt=0xAA,
            data=encrypted,
        )

    def test_event_dispatched_when_not_waiting(self):
        client = TTLockClient(_virtual_key())
        events: list[LockEvent] = []
        client.add_event_listener(events.append)
        frame = self._build_push_frame(client.key, bytes.fromhex("47012a0000"))
        client._dispatch_event(frame)
        assert len(events) == 1
        assert events[0].cmd_echo == 0x47
        assert events[0].status == 1
        assert events[0].data == bytes.fromhex("2a0000")

    def test_listener_exception_does_not_block_other_listeners(self):
        client = TTLockClient(_virtual_key())
        good_calls: list[LockEvent] = []
        client.add_event_listener(lambda _e: (_ for _ in ()).throw(RuntimeError("boom")))
        client.add_event_listener(good_calls.append)
        frame = self._build_push_frame(client.key, bytes.fromhex("47012a"))
        client._dispatch_event(frame)
        assert len(good_calls) == 1

    def test_undecodable_event_silently_swallowed(self):
        client = TTLockClient(_virtual_key())
        events: list[LockEvent] = []
        client.add_event_listener(events.append)
        # Frame with non-AES garbage; decryption will fail, listener never fires.
        bad = Frame(
            protocol_type=5,
            sub_version=3,
            scene=2,
            group_id=1,
            sub_org=1,
            command=0x54,
            encrypt=0xAA,
            data=b"\x00" * 16,
        )
        client._dispatch_event(bad)
        assert events == []
