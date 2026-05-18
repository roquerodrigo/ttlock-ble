"""TTLockClient construction and event-listener routing (no BLE I/O)."""

import asyncio
import datetime as dt
from unittest.mock import MagicMock

from ttlock_ble import LockEvent, LockState, LockVersion, TTLockClient, VirtualKey
from ttlock_ble.constants import LogOperate
from ttlock_ble.crypto import aes_decrypt, aes_encrypt, hex_key_to_bytes
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


class TestLockEventDecoding:
    """`LockEvent.from_payload` parses the cmd_echo=0x14 push variants."""

    def test_short_state_push_extracts_battery_and_state(self):
        event = LockEvent.from_payload(0x14, 1, bytes.fromhex("2c0102"))
        assert event.battery == 0x2C
        assert event.lock_state is LockState.UNLOCKED
        assert event.uid is None
        assert event.record_id is None
        assert event.timestamp is None

    def test_long_log_push_extracts_uid_record_id_timestamp(self):
        # 15-byte payload captured live: 2c=battery, then uid(4)+record_id(4)+date(6).
        payload = bytes.fromhex("2c000000006a0224a31a050b0f3008")
        event = LockEvent.from_payload(0x14, 1, payload)
        assert event.battery == 0x2C
        assert event.uid == 0
        assert event.record_id == 0x6A0224A3
        assert event.timestamp == dt.datetime(2026, 5, 11, 15, 48, 8)  # noqa: DTZ001
        assert event.lock_state is None

    def test_unknown_cmd_echo_leaves_decoded_fields_none(self):
        event = LockEvent.from_payload(0x47, 1, bytes.fromhex("2a0000"))
        assert event.cmd_echo == 0x47
        assert event.battery is None
        assert event.lock_state is None
        assert event.record_id is None
        assert event.timestamp is None
        assert event.data == bytes.fromhex("2a0000")

    def test_state_push_with_unrecognised_state_byte(self):
        event = LockEvent.from_payload(0x14, 1, bytes.fromhex("2c0502"))
        assert event.battery == 0x2C
        assert event.lock_state is None  # 5 isn't a valid lock state

    def test_log_push_with_invalid_date_returns_none_timestamp(self):
        # 0x99 as month (153) is out of range — must NOT parse as a valid date.
        payload = bytes.fromhex("2c000000006a0224a31a99010f3008")
        event = LockEvent.from_payload(0x14, 1, payload)
        assert event.uid == 0
        assert event.timestamp is None


def _operate_log_response_frame(key: VirtualKey, sequence: int, records: list[bytes]) -> Frame:
    """Build a CMD_GET_OPERATE_LOG response frame the client can decrypt.

    `sequence` is the page-level cursor the lock echoes back. Each entry
    in `records` is the variable-length record body (type+date+battery
    +payload) that `parse_operate_log_response` walks one byte-length
    prefix at a time.
    """
    payload = bytearray()
    for r in records:
        payload.append(len(r))
        payload.extend(r)
    if records:
        plain = (
            bytes([0x25, 0x01])
            + (len(payload) + 5).to_bytes(2, "big")
            + sequence.to_bytes(2, "big")
            + bytes(payload)
        )
    else:
        # Empty page: total_len==0 signals "no more entries".
        plain = bytes([0x25, 0x01, 0x00, 0x00])
    aes = hex_key_to_bytes(key.aesKeyStr)
    return Frame(
        protocol_type=key.lockVersion.protocolType,
        sub_version=key.lockVersion.protocolVersion,
        scene=key.lockVersion.scene,
        group_id=key.lockVersion.groupId,
        sub_org=key.lockVersion.orgId,
        command=0x25,
        encrypt=0xAA,
        data=aes_encrypt(plain, aes),
    )


def _keypad_record(pwd: str = "1234") -> bytes:  # noqa: S107  -- test fixture, not a real secret
    return (
        bytes([LogOperate.KEYBOARD_PASSWORD_UNLOCK])  # type
        + bytes([26, 5, 11, 14, 23, 7])  # YYMMDDhhmmss
        + bytes([45])  # battery
        + bytes([len(pwd)])
        + pwd.encode("ascii")
        + bytes([0])  # new_pwd_len
    )


class TestOperationLogPagination:
    """`get_operation_log` walks the lock log via the page-level sequence cursor."""

    def _request_sequences(self, key: VirtualKey, sent_frames: list[Frame]) -> list[int]:
        aes = hex_key_to_bytes(key.aesKeyStr)
        return [int.from_bytes(aes_decrypt(f.data, aes)[:2], "big") for f in sent_frames]

    def test_paginates_using_response_sequence_verbatim(self):
        key = _virtual_key()
        client = TTLockClient(key)
        sent: list[Frame] = []
        # Three pages, then an empty page to signal "done". Sequence direction
        # is firmware-dependent — DLock-XP V3 returns ascending sequences in
        # practice, but the cursor logic is symmetric, so the fixture uses
        # descending values to keep the off-by-one bug regression clear.
        scripted = [
            _operate_log_response_frame(key, sequence=5, records=[_keypad_record("1111")]),
            _operate_log_response_frame(key, sequence=4, records=[_keypad_record("2222")]),
            _operate_log_response_frame(key, sequence=3, records=[_keypad_record("3333")]),
            _operate_log_response_frame(key, sequence=0, records=[]),
        ]
        replies = iter(scripted)

        async def fake_exchange(frame: Frame, *, timeout: float = 6.0) -> Frame:  # noqa: ASYNC109
            sent.append(frame)
            return next(replies)

        client._exchange = fake_exchange  # type: ignore[method-assign]
        entries = asyncio.run(client.get_operation_log())

        assert [e.password for e in entries] == ["1111", "2222", "3333"]
        # First call uses 0xFFFF; each subsequent call echoes the prior response's sequence.
        assert self._request_sequences(key, sent) == [0xFFFF, 5, 4, 3]

    def test_stops_when_firmware_echoes_same_batch(self):
        # Some firmware revisions ignore our cursor and re-emit the latest entry.
        # Dedup must break the loop so we don't hang.
        key = _virtual_key()
        client = TTLockClient(key)
        sent: list[Frame] = []
        same = _keypad_record("9999")
        replies = iter(
            [
                _operate_log_response_frame(key, sequence=7, records=[same]),
                _operate_log_response_frame(key, sequence=7, records=[same]),
            ]
        )

        async def fake_exchange(frame: Frame, *, timeout: float = 6.0) -> Frame:  # noqa: ASYNC109
            sent.append(frame)
            return next(replies)

        client._exchange = fake_exchange  # type: ignore[method-assign]
        entries = asyncio.run(client.get_operation_log())

        assert len(entries) == 1
        assert entries[0].password == "9999"
        assert self._request_sequences(key, sent) == [0xFFFF, 7]

    def test_max_entries_caps_pagination(self):
        key = _virtual_key()
        client = TTLockClient(key)
        scripted = [
            _operate_log_response_frame(key, sequence=10, records=[_keypad_record("aaaa")]),
            _operate_log_response_frame(key, sequence=9, records=[_keypad_record("bbbb")]),
            _operate_log_response_frame(key, sequence=8, records=[_keypad_record("cccc")]),
        ]
        replies = iter(scripted)

        async def fake_exchange(_frame: Frame, *, timeout: float = 6.0) -> Frame:  # noqa: ASYNC109
            return next(replies)

        client._exchange = fake_exchange  # type: ignore[method-assign]
        entries = asyncio.run(client.get_operation_log(max_entries=2))
        assert [e.password for e in entries] == ["aaaa", "bbbb"]
