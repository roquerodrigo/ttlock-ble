# ttlock-ble

[![CI](https://github.com/roquerodrigo/ttlock-ble/actions/workflows/ci.yml/badge.svg)](https://github.com/roquerodrigo/ttlock-ble/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/ttlock-ble)](https://pypi.org/project/ttlock-ble/)

[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-db61a2?logo=githubsponsors&logoColor=white&style=for-the-badge)](https://github.com/sponsors/roquerodrigo)

Async Python SDK for controlling **TTLock-family smart locks** (TTLock / DLock-XP) over **Bluetooth Low Energy** — lock, unlock, state and battery, keypad passcodes, IC cards, enrolled fingerprints, auto-lock, sound, clock sync, device properties, on-device operation log, and real-time push events, with no cloud round-trip on every operation.

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

### Access levels

Not every operation needs the same credential. The **Access** column in the tables below
uses these levels:

| Access | Meaning |
| --- | --- |
| None | No TTLock credential is involved — a plain BLE read or the local key cache |
| Cloud account | The TTLock account e-mail and password (`TTLockCloud`) |
| User eKey | Any valid eKey for the lock, shared or admin — the lock either checks it with `CHECK_USER_TIME` or answers without a handshake |
| Admin eKey | The eKey of the account that owns the lock (it carries `adminPs`) — the command runs the `CHECK_ADMIN` handshake and the lock rejects anything else |

## Install

```bash
pip install ttlock-ble
```

Or, with [uv](https://docs.astral.sh/uv/):

```bash
uv add ttlock-ble
```

The `ttlock` command-line tool ships as an optional extra:

```bash
pip install "ttlock-ble[cli]"
```

Requires Python 3.14+ and a BLE adapter supported by [`bleak`](https://github.com/hbldh/bleak).

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

Accounts created in another TTLock-based app are only visible to that app's own cloud
identity. Pick it from `CLOUD_APPS` (`dlock_xp`, the default, or `schlage_breeze`):

```python
from ttlock_ble import CLOUD_APPS, TTLockCloud

async with TTLockCloud.for_app(CLOUD_APPS["schlage_breeze"]) as cloud:
    ...
```

### 2. Control a lock over BLE

```python
import asyncio
from ttlock_ble import TTLockClient

async def main(virtual_key) -> None:
    async with TTLockClient(virtual_key) as lock:   # scans + connects
        await lock.unlock()
        state, battery = await lock.query_state()
        print(state, f"{battery}%")

asyncio.run(main(keys[0]))
```

`TTLockClient` is an async context manager: it scans for `key.lockMac`, picks the GATT
service and opens the link; each command then runs the handshake it needs
(`CHECK_USER_TIME` for the bolt, `CHECK_ADMIN` for admin-gated settings — see
[Access levels](#access-levels)). Pass a pre-resolved `device=` (or use
`TTLockClient.from_ble_device(...)`) to skip the scan — that is how the Home Assistant
integration hands in a `BLEDevice` from HA's own bluetooth manager.

### Real-time events

After a command the link is kept open (`keep_alive_after_command`, 25 s by default) so
auto-lock, keypad and fingerprint operations stream back as `LockEvent`s:

```python
def on_event(event):
    print("lock event:", event)

lock.add_event_listener(on_event)
```

### Passive state, without connecting

The lock also publishes its bolt position and battery level in the manufacturer data of
every BLE advertisement. `LockAdvertisement` decodes that, so a scanner can follow the
lock without ever opening a session — the only way to observe an **auto-lock**, which the
firmware writes no log record for and cannot push once it has dropped the link:

```python
from ttlock_ble import LockAdvertisement

for company_id, payload in advertisement_data.manufacturer_data.items():
    state = LockAdvertisement.from_manufacturer_data(company_id, payload)
    if state is not None and state.lock_mac.lower() == key.lockMac.lower():
        print(state.lock_state, state.battery)
```

It returns `None` for anything that is not a stateful TTLock advertisement, and never
raises. Compare `lock_mac` against the address you expected before trusting the result
(case-insensitively — MAC casing varies between sources): a payload long enough to
decode is not proof that it came from a lock.

## CLI

Installing the package with the `cli` extra (`pip install "ttlock-ble[cli]"`) exposes a
`ttlock` command (env: `TTLOCK_EMAIL`, `TTLOCK_PASSWORD`,
optional `TTLOCK_KEY_STORE`, default `~/.ttlock/keys.json`; a `.env` file is honored):

| Command | Access | What it does |
| --- | --- | --- |
| `ttlock sync [--app <app>]` | Cloud account | Log in to the cloud and cache the account's eKeys locally; `--app` picks the TTLock-based app the account belongs to (default `dlock_xp`) |
| `ttlock verify <code> [--app <app>]` | Cloud account | Register this machine with the new-device verification code |
| `ttlock list` | None | Show cached locks |
| `ttlock unlock <lock>` | User eKey | Unlock a lock over Bluetooth |
| `ttlock lock <lock>` | User eKey | Lock a lock over Bluetooth |
| `ttlock state <lock>` | User eKey | Query current state and battery |
| `ttlock battery <lock>` | User eKey | Show battery percentage |
| `ttlock sound <lock> <on\|off>` | Admin eKey | Turn the keypad/lock beep on or off |
| `ttlock volume <lock> <1-5>` | Admin eKey | Set the keypad/lock beep volume (no-op on beeper-only hardware) |
| `ttlock get-sound <lock>` | Admin eKey | Read whether the beep is on and, when the lock reports it, its volume |
| `ttlock features <lock>` | Admin eKey | List the capabilities the lock itself advertises (`LockFeature` bits) |
| `ttlock device-info <lock>` | None | Show the standard BLE Device Information Service fields — a plain GATT read; the cached eKey only resolves the address |
| `ttlock get-device-properties <lock>` | Admin eKey | Show the 6 TTLock-proprietary device properties |
| `ttlock add-passcode <lock> <code>` | Admin eKey | Create a keypad passcode: permanent by default, `--start`/`--end` for a dated one, `--single-use` with them, or `--days`/`--from`/`--to` for a weekly one |
| `ttlock modify-passcode <lock> <code>` | Admin eKey | Change a passcode's digits (`--new-code`) and/or dates (`--start`/`--end`) |
| `ttlock delete-passcode <lock> <code>` | Admin eKey | Remove a keypad passcode |
| `ttlock clear-passcodes <lock>` | Admin eKey | Wipe ALL keypad passcodes — no undo |
| `ttlock get-passcodes <lock>` | Admin eKey | List the keypad passcodes the lock reports — **not exhaustive**: a passcode created by the official app and never yet used at the keypad does not appear |
| `ttlock get-admin-passcode <lock>` / `set-admin-passcode <lock> <code>` | Admin eKey | Print / replace the keypad admin passcode |
| `ttlock get-schedule <lock> --card <id>` / `--fingerprint <id>` | Admin eKey | Show a credential's weekly windows (ids as `get-cards` / `get-fingerprints` print them) |
| `ttlock set-schedule <lock> --card <id> --window mon=08:00-12:00 …` | Admin eKey | Replace a credential's weekly windows, after checking the lock holds it (`--window` repeats; `workdays`, `weekend` and `daily` group days) |
| `ttlock clear-schedule <lock> --card <id>` | Admin eKey | Remove a credential's weekly windows |
| `ttlock get-auto-lock <lock>` | Admin eKey | Read the auto-lock delay in seconds |
| `ttlock set-auto-lock <lock> <seconds>` | Admin eKey | Set the auto-lock delay in seconds (`0` disables it) |
| `ttlock get-auto-lock-limits <lock>` | Admin eKey | Show the min/max auto-lock delay this lock accepts |
| `ttlock get-fingerprints <lock>` | Admin eKey | List enrolled fingerprints — blind to cyclic (day-of-week / time-range) restrictions |
| `ttlock enroll-fingerprint <lock>` | Admin eKey | Enroll a fingerprint by touching the lock's sensor (prints `touch k/N` as the lock records each touch): permanent by default, same validity options as `enroll-card`; `--timeout` is the person's deadline: a finger that completes after it is deleted again, with an error (the lock keeps add mode open while touches continue). **A finger that is already enrolled is not recognised: it becomes a second, permanent entry and the finger then opens the lock through it** |
| `ttlock modify-fingerprint <lock> <id>` | Admin eKey | Replace a fingerprint's dates and weekly windows: `--permanent`, or the validity options; `<id>` is the hex id as `get-fingerprints` prints it |
| `ttlock delete-fingerprint <lock> <id>` | Admin eKey | Remove one fingerprint; asks first, `--yes`/`-y` skips the question |
| `ttlock clear-fingerprints <lock>` | Admin eKey | Remove EVERY fingerprint from the lock — no undo; asks first, `--yes`/`-y` skips the question |
| `ttlock get-cards <lock>` | Admin eKey | List enrolled IC cards/tags with their number — blind to cyclic (day-of-week / time-range) restrictions, see `get-schedule` |
| `ttlock enroll-card <lock>` | Admin eKey | Enroll a card by tapping it on the lock (asks you to present it): permanent by default, `--start`/`--end` for a dated one, `--days`/`--from`/`--to` (optionally with dates) for a weekly one; `--timeout` sets how long to wait. A card the lock already holds is restored to its previous dates and windows, with an error |
| `ttlock add-card <lock> <id>` | Admin eKey | Add a card by its hex id as `get-cards` prints it, same validity options; refuses a card the lock already holds |
| `ttlock modify-card <lock> <id>` | Admin eKey | Replace a card's dates and weekly windows: `--permanent`, or the validity options |
| `ttlock delete-card <lock> <id>` | Admin eKey | Remove one card; asks first, `--yes`/`-y` skips the question |
| `ttlock clear-cards <lock>` | Admin eKey | Remove EVERY card from the lock — no undo; asks first, `--yes`/`-y` skips the question |

Every BLE command takes `-v` for debug logging. `<lock>` is a `lockId`, alias or MAC from
`ttlock list`.

Typical first run: `ttlock sync` → (if prompted) check email → `ttlock verify <code>` →
`ttlock sync` again → `ttlock unlock <lock>`.

## API overview

Everything below is re-exported from the top-level `ttlock_ble` package.

### `TTLockClient` (BLE)

| Method | Access | Purpose |
| --- | --- | --- |
| `connect()` / `disconnect()` | — | Open / close the BLE link (or use `async with`) |
| `unlock()` / `lock()` | User eKey | Drive the bolt |
| `query_state()` | User eKey | `(LockState \| None, battery_percent \| None)` |
| `get_operation_log()` | User eKey | Paginated on-device operation log (`list[LogEntry]`) |
| `get_lock_time()` | User eKey | Read the lock's clock as a naive `datetime` in the lock's **local** time |
| `calibrate_time(local_time)` | Admin eKey | Write the lock's clock — the reference must be the lock's **local** time |
| `sync_time(local_time=…)` | User eKey; Admin eKey when it recalibrates | Read the clock, return the drift, and call `calibrate_time` only when the drift exceeds the threshold |
| `get_auto_lock_time()` / `set_auto_lock_time(seconds)` | Admin eKey | Read / set the auto-lock delay (`0` disables it) |
| `get_auto_lock_limits()` | Admin eKey | Min/max auto-lock delay this lock accepts (`AutoLockLimits`) |
| `passcodes.add(code, validity)` | Admin eKey | Create a keypad passcode: `Permanent()` (default), `Period`, `SingleUse`, or a `Weekly` schedule (one window on one weekday, Monday–Friday, the weekend or every day, whole hours, no date range) |
| `passcodes.modify(code, new_code=…, validity=…)` | Admin eKey | Change a passcode's digits and/or dates, keeping its type |
| `passcodes.delete(code)` / `passcodes.clear()` | Admin eKey | Remove one passcode / every passcode |
| `passcodes.list()` / `get_passcodes()` | Admin eKey | Keypad passcodes the lock reports (`list[PasscodeEntry]`) — **not exhaustive**: a passcode the official app generated offline won't appear until it is used at the keypad |
| `admin_passcode.get()` / `admin_passcode.set(code)` | Admin eKey | Read / replace the keypad admin passcode |
| `weekly_schedules.get(credential)` | Admin eKey | Weekly windows of a card or fingerprint (`tuple[WeeklyWindow, ...]`, empty when unrestricted) |
| `weekly_schedules.set(credential, windows)` / `weekly_schedules.clear(credential)` | Admin eKey | Replace / remove those windows; the credential's validity dates stay as they are |
| `add_passcode(...)` / `delete_passcode(...)` / `clear_passcodes()` | Admin eKey | Earlier string-based passcode calls, kept for compatibility |
| `fingerprints.list(include_weekly_windows=True)` | Admin eKey | Enrolled fingerprints with their weekly windows (`list[FingerprintEntry]`); a fingerprint without windows costs a short timeout and a reconnect, so pass `False` for a fast listing |
| `fingerprints.enroll(validity, on_progress, timeout=…)` | Admin eKey, `FINGER_PRINT` | Enroll the finger touched on the sensor; `on_progress` receives a `FingerprintEnrollmentProgress` for the ready signal, each touch and the end. `Permanent()` (default), `Period` or `Weekly`; `timeout` is a deadline for the result, not for the conversation: the call keeps listening until the lock ends add mode, raises `EnrollmentTimeoutError` when the lock gives up waiting for a finger, deletes a finger that completes after the deadline at once and raises `FingerprintEnrolledLateError` (SN478_PV53: the lock still enrolled a finger after the client gave up), and deletes the new fingerprint again if its validity cannot be applied. **Enrolling a finger the lock already holds is not detected**: the lock creates a second, permanent entry with a new id, and the finger then opens the lock through it, outside the old entry's dates and windows (captured on SN478_PV53) |
| `fingerprints.modify(fingerprint, validity)` | Admin eKey, `FINGER_PRINT` | Change a fingerprint's dates and weekly windows (`Permanent()` is not tested on hardware for fingerprints) |
| `fingerprints.delete(fingerprint)` / `fingerprints.clear()` | Admin eKey, `FINGER_PRINT` | Remove one fingerprint / every fingerprint |
| `get_fingerprints()` | Admin eKey | Enrolled fingerprints (`list[FingerprintEntry]`) without their weekly windows, as `fingerprints.list(include_weekly_windows=False)` |
| `cards.list(include_weekly_windows=True)` | Admin eKey | Enrolled IC cards with their weekly windows (`list[CardEntry]`); a card without windows costs a short timeout and a reconnect, so pass `False` for a fast listing |
| `cards.enroll(validity, on_progress, timeout=…)` | Admin eKey, `IC` | Enroll the card tapped on the lock; `Permanent()` (default), `Period` or `Weekly`; raises `EnrollmentTimeoutError` if none comes, deletes the card again if its validity cannot be applied, and restores a card the lock already held (the lock resets it) before raising `CardAlreadyEnrolledError` |
| `cards.add(card, validity)` | Admin eKey, `IC` | Add a card by its `Credential.card(number)`, without tapping; raises `CardAlreadyEnrolledError` for a card the lock holds, since the lock would replace its dates |
| `cards.modify(card, validity)` | Admin eKey, `IC` | Change a card's dates and weekly windows |
| `cards.delete(card)` / `cards.clear()` | Admin eKey, `IC` | Remove one card / every card |
| `get_cards()` | Admin eKey | Enrolled IC cards/tags (`list[CardEntry]`) without their weekly windows, as `cards.list(include_weekly_windows=False)` |
| `get_lock_sound()` | Admin eKey | Beep on/off and volume as the lock reports them (`LockSound`; `volume` is `None` on beeper-only hardware) |
| `set_lock_sound(enabled)` | Admin eKey | Turn the keypad/lock beep on or off |
| `set_lock_volume(level)` | Admin eKey | Set the keypad/lock beep volume, 1-5 or `LockVolume` (no-op on beeper-only hardware) |
| `get_device_features()` | Admin eKey | Capability bits straight from the lock (`DeviceFeatures`) — the untruncated form of the cloud's feature value; test with `supports(LockFeature.X)` |
| `get_device_info()` | None | Standard BLE Device Information Service fields (`DeviceInfo`) — plain GATT, no TTLock handshake |
| `get_device_properties()` | Admin eKey | 6 TTLock-proprietary device properties (`DeviceProperties`) — TTLock's own encrypted mechanism, distinct from `get_device_info()` |
| `add_event_listener(cb)` / `remove_event_listener(cb)` | — | Subscribe to `LockEvent` pushes |
| `is_connected` | — | Property — `True` while a connection is open |

### `TTLockCloud` (HTTP, bootstrap only)

| Method | Access | Purpose |
| --- | --- | --- |
| `TTLockCloud.for_app(app)` | — | Build a client that signs in as one of `CLOUD_APPS` (`CloudApp`) |
| `discover_site()` | None | Resolve the site for the caller's public IP, and the regional API base URL unless the app pins its own |
| `request_login_verification_code(email)` | None | Email/SMS a new-device login code |
| `validate_new_device(email, code)` | None | Register this machine with the code |
| `login(email, password)` | Cloud account | Authenticate; caches the access token |
| `list_keys()` | Cloud account | Fetch the account's eKeys as `list[VirtualKey]` — requires a prior `login()` |
| `aclose()` | — | Release the HTTP connection pool |

### Models & enums

- **Managers:** `PasscodeManager` (`client.passcodes`), `AdminPasscodeManager` (`client.admin_passcode`), `WeeklyScheduleManager` (`client.weekly_schedules`), `CardManager` (`client.cards`), `FingerprintManager` (`client.fingerprints`)
- **Credential:** `Credential.card(number)`, `Credential.fingerprint(identifier)` or `Credential.of(entry)` names a card or fingerprint for the managers
- **Models:** `VirtualKey`, `LockVersion`, `SiteInfo`, `CloudApp` (presets in `CLOUD_APPS`), `LockAdvertisement`, `LockEvent`, `LogEntry`, `DeviceInfo`, `DeviceProperties`, `DeviceFeatures`, `AutoLockLimits`, `LockSound`, `FingerprintEntry`, `FingerprintEnrollmentProgress`, `CardEntry`, `PasscodeEntry`, `CyclicSchedule`
- **Validity:** `Validity` is one of `Permanent()`, `Period(start, end)`, `SingleUse(start, end)` or `Weekly(windows, start=None, end=None)`, where each `WeeklyWindow(weekday, start, end)` covers one `Weekday` and the optional bounds limit the windows to a date range. Dates are the lock's **local** time, to the minute, between 2000 and 2099
- **Enums:** `LockState`, `AutoLockOperate`, `CredentialType`, `KeyboardPwdType`, `LockErrorCode`, `LockFeature`, `LockVolume`, `LogOperate`, `PwdOperateType`, `Weekday`
- **Exceptions:** `TTLockError` (BLE / protocol), `CloudError` (cloud HTTP). Under `TTLockError`, `LockRejectedError` carries the lock's `error_code` when it refuses a command; credential commands narrow it to `CredentialAlreadyExistsError`, `CredentialNotFoundError` or `StorageFullError`, and raise `UnsupportedFeatureError` before sending anything the lock's feature mask does not advertise. `ReplyTimeoutError` means the lock did not answer in time

`VirtualKey.has_feature(LockFeature.PASSAGE_MODE)` tells whether the lock advertises a
capability, from the feature value the cloud returns with each eKey — the same bit test the
official app performs before showing a setting.

## Home Assistant

This SDK is the transport layer for the [`ha-ttlock-ble`](https://github.com/roquerodrigo/ha-ttlock-ble)
custom integration. The integration owns BLE discovery and feeds a `BLEDevice` into
`TTLockClient.from_ble_device(...)`, so it never scans on its own.

## Development

See [`CODE_STYLE.md`](./CODE_STYLE.md) for project conventions.

```bash
uv sync
uv run ruff format --check .  # formatting
uv run ruff check .           # lint
uv run mypy src               # types
uv run pytest                 # tests (coverage gate included)
```

## Support

This SDK is built and maintained on personal time, on hardware bought for the purpose. If it is useful to you, consider [sponsoring the work](https://github.com/sponsors/roquerodrigo) — it keeps the devices, the testing and the releases coming.

## License

MIT — see [`LICENSE`](./LICENSE).
