# ttlock-ble

[![CI](https://github.com/roquerodrigo/ttlock-ble/actions/workflows/ci.yml/badge.svg)](https://github.com/roquerodrigo/ttlock-ble/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/ttlock-ble)](https://pypi.org/project/ttlock-ble/)

Async Python SDK for controlling **TTLock-family smart locks** (TTLock / DLock-XP) over **Bluetooth Low Energy** — lock, unlock, state and battery, passcode management, on-device operation log, and real-time push events, with no cloud round-trip on every operation.

> ⚠️ **Unofficial.** Not affiliated with, endorsed by, or supported by TTLock / Sciener
> or any lock vendor. It speaks the BLE V3 protocol and the cloud API the official
> mobile app uses (reverse-engineered). Either side can change and break this SDK
> without notice.

## Status

**Beta** — used in production by the [`ha-ttlock-ble`](https://github.com/roquerodrigo/ha-ttlock-ble)
Home Assistant integration. See [`CHANGELOG.md`](./CHANGELOG.md) for changes between releases.

## How it works

The lock is driven entirely over BLE, but the per-lock credentials (the "eKey") come
from the TTLock cloud once:

```
TTLockCloud (HTTP, one-time)  ──►  VirtualKey (aesKey, lockMac, …)  ──►  TTLockClient (BLE, every operation)
```

You bootstrap the eKeys from the cloud a single time (caching them locally), then every
lock/unlock happens offline over Bluetooth.

## Install

```bash
pip install ttlock-ble
```

Or, with [uv](https://docs.astral.sh/uv/):

```bash
uv add ttlock-ble
```

Requires Python 3.12+ and a BLE adapter supported by [`bleak`](https://github.com/hbldh/bleak).

## Quick start

### 1. Bootstrap eKeys from the cloud (once)

```python
import asyncio
from ttlock_ble import TTLockCloud

async def main() -> None:
    async with TTLockCloud() as cloud:
        await cloud.login("you@example.com", "your-password")
        # First time from a new machine the server requires a device check:
        #   await cloud.request_login_verification_code("you@example.com")
        #   await cloud.validate_new_device("you@example.com", code_from_email)
        keys = await cloud.list_keys()
        for k in keys:
            print(k.lockAlias, k.lockMac)

asyncio.run(main())
```

### 2. Control a lock over BLE

```python
import asyncio
from ttlock_ble import TTLockClient

async def main(virtual_key) -> None:
    async with TTLockClient(virtual_key) as lock:   # scans + connects + handshake
        await lock.unlock()
        state, battery = await lock.query_state()
        print(state, f"{battery}%")

asyncio.run(main(keys[0]))
```

`TTLockClient` is an async context manager: it scans for `key.lockMac`, picks the GATT
service, runs the `CHECK_USER_TIME` handshake, then issues commands. Pass a pre-resolved
`device=` (or use `TTLockClient.from_ble_device(...)`) to skip the scan — that is how the
Home Assistant integration hands in a `BLEDevice` from HA's own bluetooth manager.

### Real-time events

After a command the link is kept open (`keep_alive_after_command`, 25 s by default) so
auto-lock, keypad and fingerprint operations stream back as `LockEvent`s:

```python
def on_event(event):
    print("lock event:", event)

lock.add_event_listener(on_event)
```

## CLI

Installing the package exposes a `ttlock` command (env: `TTLOCK_EMAIL`, `TTLOCK_PASSWORD`,
optional `TTLOCK_KEY_STORE`, default `~/.ttlock/keys.json`; a `.env` file is honored):

| Command | What it does |
| --- | --- |
| `ttlock sync` | Log in to the cloud and cache the account's eKeys locally |
| `ttlock verify <code>` | Register this machine with the new-device verification code |
| `ttlock list` | Show cached locks |
| `ttlock unlock <lock>` | Unlock a lock over Bluetooth |
| `ttlock lock <lock>` | Lock a lock over Bluetooth |
| `ttlock state <lock>` | Query current state and battery |
| `ttlock battery <lock>` | Show battery percentage |

Typical first run: `ttlock sync` → (if prompted) check email → `ttlock verify <code>` →
`ttlock sync` again → `ttlock unlock <lock>`.

## API overview

Everything below is re-exported from the top-level `ttlock_ble` package.

### `TTLockClient` (BLE)

| Method | Purpose |
| --- | --- |
| `connect()` / `disconnect()` | Open / close the BLE link (or use `async with`) |
| `unlock()` / `lock()` | Drive the bolt |
| `query_state()` | `(LockState \| None, battery_percent \| None)` |
| `get_auto_lock_time()` / `set_auto_lock_time(seconds)` | Read / set the auto-lock delay |
| `add_passcode(...)` / `delete_passcode(...)` / `clear_passcodes()` | Manage keypad passcodes |
| `get_operation_log()` | Paginated on-device operation log (`list[LogEntry]`) |
| `get_lock_time()` / `calibrate_time()` / `sync_time()` | Read / align the lock's clock |
| `add_event_listener(cb)` / `remove_event_listener(cb)` | Subscribe to `LockEvent` pushes |
| `is_connected` | Property — `True` while a connection is open |

### `TTLockCloud` (HTTP, bootstrap only)

| Method | Purpose |
| --- | --- |
| `login(email, password)` | Authenticate; caches the access token |
| `request_login_verification_code(email)` | Email/SMS a new-device login code |
| `validate_new_device(email, code)` | Register this machine with the code |
| `discover_site()` | Resolve the regional API base URL / site |
| `list_keys()` | Fetch the account's eKeys as `list[VirtualKey]` |
| `aclose()` | Release the HTTP connection pool |

### Models & enums

- **Models:** `VirtualKey`, `LockVersion`, `SiteInfo`, `LockEvent`, `LogEntry`
- **Enums:** `LockState`, `AutoLockOperate`, `KeyboardPwdType`, `LogOperate`, `PwdOperateType`
- **Exceptions:** `TTLockError` (BLE / protocol), `CloudError` (cloud HTTP)

## Home Assistant

This SDK is the transport layer for the [`ha-ttlock-ble`](https://github.com/roquerodrigo/ha-ttlock-ble)
custom integration. The integration owns BLE discovery and feeds a `BLEDevice` into
`TTLockClient.from_ble_device(...)`, so it never scans on its own.

## Development

See [`CODE_STYLE.md`](./CODE_STYLE.md) for project conventions.

```bash
uv sync
uv run pytest        # tests
uv run ruff check .  # lint
uv run mypy src      # types
```

## License

MIT — see [`LICENSE`](./LICENSE).
