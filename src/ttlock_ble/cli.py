"""Typer-powered `ttlock` CLI: locks, state, sound, device info, passcodes, fingerprints, cards."""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

import typer
from dotenv import load_dotenv

from . import commands as cmd
from ._cloud_helpers import ERR_NEW_DEVICE_LOGIN
from .client import TTLockClient
from .cloud import TTLockCloud
from .constants import (
    CardEnrollmentStep,
    CredentialType,
    FingerprintEnrollmentStep,
    KeyboardPwdType,
    LockVolume,
    Weekday,
)
from .credentials.card_manager import ENROLL_SAFETY_WINDOW
from .credentials.fingerprint_manager import DEFAULT_ENROLL_TIMEOUT
from .exceptions import CloudError, TTLockError
from .models import (
    CLOUD_APPS,
    AutoLockLimits,
    CardEntry,
    CloudApp,
    Credential,
    DeviceFeatures,
    DeviceInfo,
    DeviceProperties,
    FingerprintEntry,
    LockSound,
    PasscodeEntry,
    Period,
    Permanent,
    SingleUse,
    Validity,
    VirtualKey,
    Weekly,
    WeeklyWindow,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from .constants import LockState
    from .models import FingerprintEnrollmentProgress

app = typer.Typer(add_completion=False, help="DLock-XP / TTLock BLE control")
KEY_STORE = Path(os.environ.get("TTLOCK_KEY_STORE", "~/.ttlock/keys.json")).expanduser()

# "custom" is the official app's own label for PERIOD.
_PASSCODE_TYPE_LABELS = {
    KeyboardPwdType.PERMANENT: "permanent",
    KeyboardPwdType.COUNT: "single-use",
    KeyboardPwdType.PERIOD: "custom",
    KeyboardPwdType.CIRCLE: "cyclic",
}


_DAY_GROUPS: dict[str, tuple[Weekday, ...]] = {
    "daily": tuple(Weekday),
    "workdays": tuple(day for day in Weekday if day < Weekday.SATURDAY),
    "weekend": (Weekday.SATURDAY, Weekday.SUNDAY),
}
_DAY_NAMES = {day.name[:3].lower(): day for day in Weekday}


def _parse_moment(value: str, option: str) -> dt.datetime:
    try:
        return dt.datetime.fromisoformat(value)
    except ValueError:
        raise typer.BadParameter(f"{option} must look like 2026-12-24T18:00") from None


def _parse_days(value: str) -> tuple[Weekday, ...]:
    if value in _DAY_GROUPS:
        return _DAY_GROUPS[value]
    try:
        return tuple(_DAY_NAMES[name.strip()] for name in value.split(","))
    except KeyError:
        names = ", ".join([*_DAY_GROUPS, *_DAY_NAMES])
        raise typer.BadParameter(f"--days takes {names}, or a comma-separated list") from None


def _parse_time(value: str, option: str) -> dt.time:
    try:
        return dt.time.fromisoformat(value)
    except ValueError:
        raise typer.BadParameter(f"{option} must look like 17:30") from None


def _passcode_validity(
    *,
    start: str | None,
    end: str | None,
    single_use: bool,
    days: str | None,
    window_start: str | None,
    window_end: str | None,
) -> Validity:
    try:
        if days is not None:
            if window_start is None or window_end is None:
                raise typer.BadParameter("--days needs --from and --to")
            if start is not None or end is not None or single_use:
                raise typer.BadParameter(
                    "a weekly passcode repeats without a date range or single use: "
                    "drop --start, --end and --single-use"
                )
            opens = _parse_time(window_start, "--from")
            closes = _parse_time(window_end, "--to")
            return Weekly(tuple(WeeklyWindow(day, opens, closes) for day in _parse_days(days)))
        if window_start is not None or window_end is not None:
            raise typer.BadParameter("--from and --to need --days")
        if start is None and end is None:
            if single_use:
                raise typer.BadParameter("--single-use needs --start and --end")
            return Permanent()
        if start is None or end is None:
            raise typer.BadParameter("--start and --end go together")
        kind = SingleUse if single_use else Period
        return kind(_parse_moment(start, "--start"), _parse_moment(end, "--end"))
    except ValueError as error:
        raise typer.BadParameter(str(error)) from None


def _dated_validity(
    *,
    start: str | None,
    end: str | None,
    days: str | None,
    window_start: str | None,
    window_end: str | None,
) -> Validity:
    """Build a card's validity: like a passcode's, but `--days` may also carry a date range."""
    if days is None:
        return _passcode_validity(
            start=start,
            end=end,
            single_use=False,
            days=None,
            window_start=window_start,
            window_end=window_end,
        )
    weekly = _passcode_validity(
        start=None,
        end=None,
        single_use=False,
        days=days,
        window_start=window_start,
        window_end=window_end,
    )
    if start is None and end is None:
        return weekly
    if start is None or end is None:
        raise typer.BadParameter("--start and --end go together")
    try:
        return Weekly(
            weekly.windows if isinstance(weekly, Weekly) else (),
            _parse_moment(start, "--start"),
            _parse_moment(end, "--end"),
        )
    except ValueError as error:
        raise typer.BadParameter(str(error)) from None


def _card_credential(card_id: str) -> Credential:
    return _schedule_credential(card_id, None)


def _fingerprint_credential(fingerprint_id: str) -> Credential:
    return _schedule_credential(None, fingerprint_id)


def _validate[T](build: Callable[[], T]) -> T:
    """Run a payload builder before connecting, so bad input is a usage error."""
    try:
        return build()
    except ValueError as error:
        raise typer.BadParameter(str(error)) from None


def _parse_window(value: str) -> tuple[WeeklyWindow, ...]:
    days, separator, hours = value.partition("=")
    opens, dash, closes = hours.partition("-")
    if not separator or not dash:
        raise typer.BadParameter(f"--window {value!r} must look like mon=08:00-12:00")
    start = _parse_time(opens, "--window")
    end = _parse_time(closes, "--window")
    try:
        return tuple(WeeklyWindow(day, start, end) for day in _parse_days(days))
    except ValueError as error:
        raise typer.BadParameter(str(error)) from None


def _schedule_credential(card: str | None, fingerprint: str | None) -> Credential:
    if (card is None) == (fingerprint is None):
        raise typer.BadParameter("give exactly one of --card or --fingerprint")
    try:
        if card is not None:
            return Credential(CredentialType.CARD, bytes.fromhex(card))
        return Credential.fingerprint(bytes.fromhex(fingerprint or ""))
    except ValueError as error:
        raise typer.BadParameter(f"credential id: {error}") from None


def _describe(credential: Credential) -> str:
    kind = "card" if credential.card_number is not None else "fingerprint"
    return f"{kind} {credential.identifier.hex()}"


def _echo_windows(windows: tuple[WeeklyWindow, ...]) -> None:
    if not windows:
        typer.echo(
            "no weekly windows: works whenever its dates allow, "
            "or the lock does not hold this credential"
        )
    for window in windows:
        typer.echo(f"  {window.weekday.name.title():<9} {window.start:%H:%M}-{window.end:%H:%M}")


def _load_env() -> tuple[str, str]:
    load_dotenv()
    email = os.environ.get("TTLOCK_EMAIL")
    password = os.environ.get("TTLOCK_PASSWORD")
    if not email or not password:
        raise typer.BadParameter("Set TTLOCK_EMAIL and TTLOCK_PASSWORD in .env or environment")
    return email, password


def _load_keys() -> list[VirtualKey]:
    if not KEY_STORE.exists():
        raise typer.BadParameter(f"No keys cached at {KEY_STORE} — run `ttlock sync` first")
    raw = json.loads(KEY_STORE.read_text())
    return [VirtualKey.from_dict(d) for d in raw]


def _resolve_key(target: str) -> VirtualKey:
    keys = _load_keys()
    for k in keys:
        if str(k.lockId) == target or k.lockAlias == target or k.lockMac.upper() == target.upper():
            return k
    raise typer.BadParameter(
        f"No key matches '{target}'. Available: "
        + ", ".join(f"{k.lockId}({k.lockAlias})" for k in keys)
    )


def _resolve_cloud_app(name: str) -> CloudApp:
    try:
        return CLOUD_APPS[name]
    except KeyError:
        raise typer.BadParameter(
            f"Unknown app '{name}'. Available: " + ", ".join(CLOUD_APPS)
        ) from None


_CLOUD_APP_OPTION_HELP = "TTLock-based app the account belongs to: " + ", ".join(CLOUD_APPS)


@app.command()
def sync(
    verbose: bool = typer.Option(False, "-v", help="HTTP debug logs"),
    app_name: str = typer.Option("dlock_xp", "--app", help=_CLOUD_APP_OPTION_HELP),
) -> None:
    """Log in to the TTLock cloud and cache the user's eKeys locally."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    cloud_app = _resolve_cloud_app(app_name)
    email, password = _load_env()
    keys = asyncio.run(_run_sync(cloud_app, email, password))
    KEY_STORE.parent.mkdir(parents=True, exist_ok=True)
    KEY_STORE.write_text(json.dumps([k.to_dict() for k in keys], indent=2))
    typer.echo(f"saved → {KEY_STORE}")


@app.command()
def verify(
    code: str = typer.Argument(..., help="Verification code from email/SMS"),
    verbose: bool = typer.Option(False, "-v"),
    app_name: str = typer.Option("dlock_xp", "--app", help=_CLOUD_APP_OPTION_HELP),
) -> None:
    """Register this machine with TTLock using the verification code."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    cloud_app = _resolve_cloud_app(app_name)
    email, _ = _load_env()
    asyncio.run(_run_verify(cloud_app, email, code))
    typer.echo("✓ device registered. Now run `ttlock sync`.")


async def _run_sync(cloud_app: CloudApp, email: str, password: str) -> list[VirtualKey]:
    async with TTLockCloud.for_app(cloud_app) as cloud:
        try:
            await cloud.discover_site()
        except CloudError as exc:
            typer.echo(f"warning: site discovery failed ({exc}); using default")
        try:
            creds = await cloud.login(email, password)
        except CloudError as exc:
            if exc.body.get("errorCode") == ERR_NEW_DEVICE_LOGIN:
                typer.echo(
                    "this device is not registered with TTLock yet — "
                    "requesting a verification code…"
                )
                await cloud.request_login_verification_code(email)
                typer.echo(f"code sent to {email}.\ncheck inbox, then run:\n  ttlock verify <code>")
                raise typer.Exit(2) from None
            raise
        typer.echo(f"logged in as uid={creds.uid}")
        keys = await cloud.list_keys()
        typer.echo(f"fetched {len(keys)} key(s)")
        return keys


async def _run_verify(cloud_app: CloudApp, email: str, code: str) -> None:
    async with TTLockCloud.for_app(cloud_app) as cloud:
        with contextlib.suppress(CloudError):
            await cloud.discover_site()
        await cloud.validate_new_device(email, code)


@app.command("list")
def list_keys() -> None:
    """Show cached locks."""
    for k in _load_keys():
        typer.echo(
            f"  lockId={k.lockId:<6}  mac={k.lockMac:<18}  "
            f"alias={k.lockAlias or k.lockName!r}  "
            f"role={'admin' if k.is_admin() else 'user'}  "
            f"protocol={k.lockVersion.protocolType}.{k.lockVersion.protocolVersion}"
        )


@app.command()
def unlock(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Unlock a lock via Bluetooth."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    key = _resolve_key(target)
    asyncio.run(_run_unlock(key))
    typer.echo("✓ unlocked")


@app.command()
def lock(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Lock a lock via Bluetooth."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    key = _resolve_key(target)
    asyncio.run(_run_lock(key))
    typer.echo("✓ locked")


@app.command()
def state(
    target: str = typer.Argument(...),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Query the lock's current state and battery."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    key = _resolve_key(target)
    s, batt = asyncio.run(_run_state(key))
    label = s.name if s is not None else "UNKNOWN"
    state_value = int(s) if s is not None else "?"
    batt_str = f"{batt}%" if batt is not None else "?"
    typer.echo(f"state: {label} ({state_value})  battery: {batt_str}")


@app.command()
def battery(
    target: str = typer.Argument(...),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Show battery percentage."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    key = _resolve_key(target)
    _s, batt = asyncio.run(_run_state(key))
    if batt is None:
        typer.echo("battery: unknown")
        raise typer.Exit(1)
    typer.echo(f"battery: {batt}%")


@app.command()
def sound(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    state: str = typer.Argument(..., help="'on' or 'off'"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Turn the keypad/lock beep on or off (requires an admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    if state not in {"on", "off"}:
        raise typer.BadParameter("state must be 'on' or 'off'")
    key = _resolve_key(target)
    asyncio.run(_run_sound(key, enabled=state == "on"))
    typer.echo(f"✓ sound {state}")


@app.command()
def volume(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    level: int = typer.Argument(..., help="1 (lowest) to 5 (highest)"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Set the keypad/lock beep volume (requires an admin eKey; no-op on beeper-only hardware)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    # Checked here, before anything opens a session: the client rejects an
    # out-of-range level too, but only after connecting, and waking a
    # battery lock to tell the user they typed a 9 is a poor trade.
    if level not in LockVolume:
        raise typer.BadParameter(f"level must be {min(LockVolume)}-{max(LockVolume)}")
    key = _resolve_key(target)
    asyncio.run(_run_volume(key, level))
    typer.echo(f"✓ volume set to {level}")


@app.command("get-sound")
def get_sound(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Read whether the keypad/lock beep is on and its volume (requires an admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    key = _resolve_key(target)
    sound = asyncio.run(_run_get_sound(key))
    volume = (
        "not reported" if sound.volume is None else f"{int(sound.volume)} ({sound.volume.name})"
    )
    typer.echo(f"sound: {'on' if sound.enabled else 'off'}  volume: {volume}")


@app.command("features")
def features(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """List the capabilities the lock itself advertises (requires an admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    key = _resolve_key(target)
    device_features = asyncio.run(_run_features(key))
    typer.echo(
        f"feature value: {device_features.feature_value}  battery: {device_features.battery}%"
    )
    for feature in device_features.known:
        typer.echo(f"  {int(feature):>3}  {feature.name}")
    for bit in device_features.unnamed_bits:
        typer.echo(f"  {bit:>3}  (no name in the SDK mirror)")
    if key.featureValue and key.feature_mask != device_features.mask:
        typer.echo(f"note: the cached eKey carries a different feature value ({key.featureValue})")


@app.command("device-info")
def device_info(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Read the standard BLE Device Information Service fields (no handshake needed)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    key = _resolve_key(target)
    info = asyncio.run(_run_device_info(key))
    typer.echo(f"manufacturer:      {info.manufacturer or '?'}")
    typer.echo(f"model:             {info.model or '?'}")
    typer.echo(f"serial number:     {info.serial_number or '?'}")
    typer.echo(f"hardware revision: {info.hardware_revision or '?'}")
    typer.echo(f"firmware revision: {info.firmware_revision or '?'}")
    typer.echo(f"software revision: {info.software_revision or '?'}")


@app.command("get-device-properties")
def get_device_properties(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Read the 6 TTLock-proprietary device properties (requires an admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    key = _resolve_key(target)
    properties = asyncio.run(_run_get_device_properties(key))
    typer.echo(f"model variant:     {properties.model_variant}")
    typer.echo(f"hardware revision: {properties.hardware_revision}")
    typer.echo(f"firmware version:  {properties.firmware_version}")
    typer.echo(f"manufacture date:  {properties.manufacture_date}")
    typer.echo(f"MAC address:       {properties.mac_address}")
    typer.echo(f"clock time:        {properties.clock_time.isoformat(sep=' ')}")


@app.command("add-passcode")
def add_passcode(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    code: str = typer.Argument(..., help="4-9 digit passcode"),
    start: str | None = typer.Option(None, help="valid from, lock-local ISO time"),
    end: str | None = typer.Option(None, help="valid until, lock-local ISO time"),
    single_use: bool = typer.Option(False, "--single-use", help="works once, between the dates"),
    days: str | None = typer.Option(None, help="weekly: daily, workdays, weekend, or one day"),
    window_start: str | None = typer.Option(None, "--from", help="weekly window start, HH:MM"),
    window_end: str | None = typer.Option(None, "--to", help="weekly window end, HH:MM"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Create a keypad passcode: permanent, dated, single-use or weekly (admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    validity = _passcode_validity(
        start=start,
        end=end,
        single_use=single_use,
        days=days,
        window_start=window_start,
        window_end=window_end,
    )
    if isinstance(validity, Weekly):
        _validate(lambda: cmd.payload_passcode_recover_weekly(code, validity))
    else:
        _validate(lambda: cmd.payload_passcode_create(code, validity))
    key = _resolve_key(target)
    asyncio.run(_run_add_passcode(key, code, validity))
    typer.echo(f"✓ passcode {code} added")


@app.command("modify-passcode")
def modify_passcode(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    code: str = typer.Argument(..., help="the passcode to change"),
    new_code: str | None = typer.Option(None, help="replacement digits"),
    start: str | None = typer.Option(None, help="new start, lock-local ISO time"),
    end: str | None = typer.Option(None, help="new end, lock-local ISO time"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Change a passcode's digits and/or dates, keeping its type (admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    validity: Period | None = None
    if start is not None or end is not None:
        dated = _passcode_validity(
            start=start, end=end, single_use=False, days=None, window_start=None, window_end=None
        )
        validity = dated if isinstance(dated, Period) else None
    if new_code is None and validity is None:
        raise typer.BadParameter("give --new-code, or --start with --end")
    _validate(lambda: cmd.payload_passcode_modify(code, new_code=new_code, validity=validity))
    key = _resolve_key(target)
    asyncio.run(_run_modify_passcode(key, code, new_code, validity))
    typer.echo(f"✓ passcode {new_code or code} updated")


@app.command("get-admin-passcode")
def get_admin_passcode(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Print the keypad admin passcode (admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    key = _resolve_key(target)
    typer.echo(asyncio.run(_run_get_admin_passcode(key)))


@app.command("set-admin-passcode")
def set_admin_passcode(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    code: str = typer.Argument(..., help="new 4-9 digit admin passcode"),
    yes: bool = typer.Option(False, "--yes", "-y", help="skip the confirmation prompt"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Replace the keypad admin passcode (admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    _validate(lambda: cmd.payload_set_admin_passcode(code))
    key = _resolve_key(target)
    if not yes:
        typer.confirm(
            f"Replace the admin passcode of {key.lockAlias or key.lockMac}?",
            abort=True,
        )
    asyncio.run(_run_set_admin_passcode(key, code))
    typer.echo("✓ admin passcode updated")


@app.command("delete-passcode")
def delete_passcode(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    code: str = typer.Argument(..., help="passcode to remove"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Remove a keypad passcode (requires an admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    _validate(lambda: cmd.check_passcode(code))
    key = _resolve_key(target)
    asyncio.run(_run_delete_passcode(key, code))
    typer.echo(f"✓ passcode {code} removed")


@app.command("clear-passcodes")
def clear_passcodes(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    yes: bool = typer.Option(False, "--yes", "-y", help="skip the confirmation prompt"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Wipe ALL keypad passcodes from the lock - no undo (requires an admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    key = _resolve_key(target)
    if not yes:
        typer.confirm(
            f"Wipe every keypad passcode from {key.lockAlias or key.lockMac}?",
            abort=True,
        )
    asyncio.run(_run_clear_passcodes(key))
    typer.echo("✓ all passcodes cleared")


@app.command("get-passcodes")
def get_passcodes(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """List keypad passcodes visible to this query (requires an admin eKey).

    NOT exhaustive: a passcode never added through this library, and
    never yet physically used at the keypad, will not appear here even
    though it is active and valid on the lock.
    """
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    key = _resolve_key(target)
    entries = asyncio.run(_run_get_passcodes(key))
    if not entries:
        typer.echo("no passcodes visible to this query")
    for entry in entries:
        label = _PASSCODE_TYPE_LABELS.get(entry.pwd_type, entry.pwd_type.name)
        typer.echo(f"  passcode={entry.passcode}  type={label}")
        if entry.cyclic_schedule is not None:
            schedule = entry.cyclic_schedule
            typer.echo(
                f"    schedule: {schedule.day_or_preset} "
                f"{schedule.start_hour:02d}:{schedule.start_minute:02d}"
                f"-{schedule.end_hour:02d}:00 ({schedule.duration_hours}h)"
            )
        elif entry.start_date is not None and entry.end_date is not None:
            typer.echo(
                f"    start={entry.start_date.isoformat(sep=' ')}  "
                f"end={entry.end_date.isoformat(sep=' ')}"
            )
        elif entry.start_date is not None:
            typer.echo(f"    permanent (start={entry.start_date.isoformat(sep=' ')})")
    typer.echo(
        "note: this list is not exhaustive - a passcode never added through "
        "this library, and never yet used at the keypad, will not appear here."
    )


@app.command("get-auto-lock")
def get_auto_lock(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Read the auto-lock delay in seconds (requires an admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    key = _resolve_key(target)
    seconds = asyncio.run(_run_get_auto_lock(key))
    typer.echo(f"auto-lock: {seconds}s" if seconds >= 0 else "auto-lock: unknown")


@app.command("set-auto-lock")
def set_auto_lock(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    seconds: int = typer.Argument(..., help="delay in seconds ('0' disables auto-lock)"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Set the auto-lock delay in seconds (requires an admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    key = _resolve_key(target)
    asyncio.run(_run_set_auto_lock(key, seconds))
    typer.echo(f"✓ auto-lock set to {seconds}s")


@app.command("get-auto-lock-limits")
def get_auto_lock_limits(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Read the min/max auto-lock delay accepted by this lock (requires an admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    key = _resolve_key(target)
    limits = asyncio.run(_run_get_auto_lock_limits(key))
    typer.echo(f"min: {limits.min_allowed}s")
    typer.echo(f"max: {limits.max_allowed}s")


@app.command("get-fingerprints")
def get_fingerprints(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """List enrolled fingerprints (requires an admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    key = _resolve_key(target)
    entries = asyncio.run(_run_get_fingerprints(key))
    if not entries:
        typer.echo("no fingerprints enrolled")
    for entry in entries:
        start = "not set" if entry.start_date is None else entry.start_date.isoformat(sep=" ")
        end = "permanent" if entry.end_date is None else entry.end_date.isoformat(sep=" ")
        typer.echo(f"  id={entry.identifier.hex()}  start={start}  end={end}")
    typer.echo("note: weekly windows are not listed here - see get-schedule.")


_CARD_HELP = "card id, in hex as get-cards prints it"
_START_HELP = "valid from, lock-local ISO time"
_END_HELP = "valid until, lock-local ISO time"
_DAYS_HELP = "weekly: daily, workdays, weekend, or one day; with --from and --to"


def _run_credential_command[T](coroutine: Coroutine[object, object, T]) -> T:
    """Run a card or fingerprint command; a library error becomes one error line and exit 1."""
    try:
        return asyncio.run(coroutine)
    except TTLockError as error:
        typer.echo(f"error: {error}", err=True)
        raise typer.Exit(1) from None


@app.command("enroll-card")
def enroll_card(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    start: str | None = typer.Option(None, help=_START_HELP),
    end: str | None = typer.Option(None, help=_END_HELP),
    days: str | None = typer.Option(None, help=_DAYS_HELP),
    window_start: str | None = typer.Option(None, "--from", help="weekly window start, HH:MM"),
    window_end: str | None = typer.Option(None, "--to", help="weekly window end, HH:MM"),
    timeout: float = typer.Option(
        ENROLL_SAFETY_WINDOW,
        help="seconds to wait for the card; the lock may listen about 10-20 s after that, "
        "so the command waits at least 30 s in all",
    ),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Enroll a card by tapping it on the lock: permanent, dated or weekly (admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    validity = _dated_validity(
        start=start, end=end, days=days, window_start=window_start, window_end=window_end
    )
    _validate(lambda: cmd.check_card_validity(validity))
    key = _resolve_key(target)
    credential = _run_credential_command(_run_enroll_card(key, validity, timeout))
    typer.echo(
        f"✓ card enrolled: id {credential.identifier.hex()} (number {credential.card_number})"
    )


@app.command("add-card")
def add_card(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    card_id: str = typer.Argument(..., help=_CARD_HELP),
    start: str | None = typer.Option(None, help=_START_HELP),
    end: str | None = typer.Option(None, help=_END_HELP),
    days: str | None = typer.Option(None, help=_DAYS_HELP),
    window_start: str | None = typer.Option(None, "--from", help="weekly window start, HH:MM"),
    window_end: str | None = typer.Option(None, "--to", help="weekly window end, HH:MM"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Add a card by its id, without tapping it (admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    validity = _dated_validity(
        start=start, end=end, days=days, window_start=window_start, window_end=window_end
    )
    card = _card_credential(card_id)
    _validate(lambda: cmd.payload_card_add(card.identifier, validity))
    key = _resolve_key(target)
    _run_credential_command(_run_add_card(key, card, validity))
    typer.echo(f"✓ card {card_id} added")


@app.command("modify-card")
def modify_card(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    card_id: str = typer.Argument(..., help=_CARD_HELP),
    permanent: bool = typer.Option(False, "--permanent", help="remove its dates and windows"),
    start: str | None = typer.Option(None, help=_START_HELP),
    end: str | None = typer.Option(None, help=_END_HELP),
    days: str | None = typer.Option(None, help=_DAYS_HELP),
    window_start: str | None = typer.Option(None, "--from", help="weekly window start, HH:MM"),
    window_end: str | None = typer.Option(None, "--to", help="weekly window end, HH:MM"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Replace a card's dates and weekly windows (admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    given = any(value is not None for value in (start, end, days, window_start, window_end))
    if permanent == given:
        raise typer.BadParameter("give --permanent, or the new dates and/or --days")
    validity = _dated_validity(
        start=start, end=end, days=days, window_start=window_start, window_end=window_end
    )
    card = _card_credential(card_id)
    _validate(lambda: cmd.payload_card_modify(card.identifier, validity))
    key = _resolve_key(target)
    _run_credential_command(_run_modify_card(key, card, validity))
    typer.echo(f"✓ card {card_id} updated")


@app.command("delete-card")
def delete_card(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    card_id: str = typer.Argument(..., help=_CARD_HELP),
    yes: bool = typer.Option(False, "--yes", "-y", help="skip the confirmation prompt"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Remove one card (admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    card = _card_credential(card_id)
    key = _resolve_key(target)
    if not yes:
        typer.confirm(f"Remove card {card_id} from {key.lockAlias or key.lockMac}?", abort=True)
    _run_credential_command(_run_delete_card(key, card))
    typer.echo(f"✓ card {card_id} removed")


@app.command("clear-cards")
def clear_cards(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    yes: bool = typer.Option(False, "--yes", "-y", help="skip the confirmation prompt"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Remove EVERY card from the lock - no undo (admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    key = _resolve_key(target)
    if not yes:
        typer.confirm(
            f"This removes EVERY card from {key.lockAlias or key.lockMac}, not just one. Continue?",
            abort=True,
        )
    _run_credential_command(_run_clear_cards(key))
    typer.echo("✓ all cards cleared")


@app.command("get-cards")
def get_cards(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """List enrolled IC cards/tags (requires an admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    key = _resolve_key(target)
    entries = asyncio.run(_run_get_cards(key))
    if not entries:
        typer.echo("no cards enrolled")
    for entry in entries:
        start = "not set" if entry.start_date is None else entry.start_date.isoformat(sep=" ")
        end = "permanent" if entry.end_date is None else entry.end_date.isoformat(sep=" ")
        number = int.from_bytes(entry.card_id, "big")
        typer.echo(f"  id={entry.card_id.hex()}  number={number}  start={start}  end={end}")
    typer.echo("note: weekly windows are not listed here - see get-schedule.")


_FINGERPRINT_HELP = "fingerprint id, in hex as get-fingerprints prints it"
_WINDOW_OPTION = typer.Option(
    ..., help="DAYS=HH:MM-HH:MM, e.g. mon=08:00-12:00 or workdays=08:00-18:00; repeatable"
)


@app.command("get-schedule")
def get_schedule(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    card: str | None = typer.Option(None, help=_CARD_HELP),
    fingerprint: str | None = typer.Option(None, help=_FINGERPRINT_HELP),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Show the weekly windows of a card or fingerprint (admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    credential = _schedule_credential(card, fingerprint)
    key = _resolve_key(target)
    _echo_windows(asyncio.run(_run_get_schedule(key, credential)))


@app.command("set-schedule")
def set_schedule(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    window: list[str] = _WINDOW_OPTION,
    card: str | None = typer.Option(None, help=_CARD_HELP),
    fingerprint: str | None = typer.Option(None, help=_FINGERPRINT_HELP),
    yes: bool = typer.Option(False, "--yes", "-y", help="skip the confirmation prompt"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Replace the weekly windows of a card or fingerprint; its dates stay as they are."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    credential = _schedule_credential(card, fingerprint)
    windows = tuple(item for value in window for item in _parse_window(value))
    _validate(lambda: Weekly(windows))
    key = _resolve_key(target)
    if not yes:
        typer.confirm(
            f"Replace the weekly windows of {_describe(credential)} on "
            f"{key.lockAlias or key.lockMac}?",
            abort=True,
        )
    asyncio.run(_run_set_schedule(key, credential, windows))
    typer.echo(f"✓ {len(windows)} weekly window(s) set")


@app.command("clear-schedule")
def clear_schedule(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    card: str | None = typer.Option(None, help=_CARD_HELP),
    fingerprint: str | None = typer.Option(None, help=_FINGERPRINT_HELP),
    yes: bool = typer.Option(False, "--yes", "-y", help="skip the confirmation prompt"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Remove the weekly windows, so the credential works whenever its dates allow."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    credential = _schedule_credential(card, fingerprint)
    key = _resolve_key(target)
    if not yes:
        typer.confirm(
            f"Remove the weekly windows of {_describe(credential)} on "
            f"{key.lockAlias or key.lockMac}?",
            abort=True,
        )
    asyncio.run(_run_clear_schedule(key, credential))
    typer.echo("✓ weekly windows removed")


@app.command("enroll-fingerprint")
def enroll_fingerprint(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    start: str | None = typer.Option(None, help=_START_HELP),
    end: str | None = typer.Option(None, help=_END_HELP),
    days: str | None = typer.Option(None, help=_DAYS_HELP),
    window_start: str | None = typer.Option(None, "--from", help="weekly window start, HH:MM"),
    window_end: str | None = typer.Option(None, "--to", help="weekly window end, HH:MM"),
    timeout: float = typer.Option(
        DEFAULT_ENROLL_TIMEOUT,
        help="seconds the person has to finish; a finger completing after that is removed "
        "again with an error (the lock ends enrollment itself after about 8 s without a touch)",
    ),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Enroll a fingerprint by touching the lock's sensor: permanent, dated or weekly (admin eKey).

    A finger that is already enrolled is not recognised: it becomes a second,
    permanent entry, and the finger then opens the lock through that entry.
    """
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    validity = _dated_validity(
        start=start, end=end, days=days, window_start=window_start, window_end=window_end
    )
    _validate(lambda: cmd.check_fingerprint_validity(validity))
    key = _resolve_key(target)
    credential = _run_credential_command(_run_enroll_fingerprint(key, validity, timeout))
    typer.echo(f"✓ fingerprint enrolled: id {credential.identifier.hex()}")


@app.command("modify-fingerprint")
def modify_fingerprint(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    fingerprint_id: str = typer.Argument(..., help=_FINGERPRINT_HELP),
    permanent: bool = typer.Option(False, "--permanent", help="remove its dates and windows"),
    start: str | None = typer.Option(None, help=_START_HELP),
    end: str | None = typer.Option(None, help=_END_HELP),
    days: str | None = typer.Option(None, help=_DAYS_HELP),
    window_start: str | None = typer.Option(None, "--from", help="weekly window start, HH:MM"),
    window_end: str | None = typer.Option(None, "--to", help="weekly window end, HH:MM"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Replace a fingerprint's dates and weekly windows (admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    given = any(value is not None for value in (start, end, days, window_start, window_end))
    if permanent == given:
        raise typer.BadParameter("give --permanent, or the new dates and/or --days")
    validity = _dated_validity(
        start=start, end=end, days=days, window_start=window_start, window_end=window_end
    )
    fingerprint = _fingerprint_credential(fingerprint_id)
    _validate(lambda: cmd.payload_fingerprint_modify(fingerprint.identifier, validity))
    key = _resolve_key(target)
    _run_credential_command(_run_modify_fingerprint(key, fingerprint, validity))
    typer.echo(f"✓ fingerprint {fingerprint_id} updated")


@app.command("delete-fingerprint")
def delete_fingerprint(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    fingerprint_id: str = typer.Argument(..., help=_FINGERPRINT_HELP),
    yes: bool = typer.Option(False, "--yes", "-y", help="skip the confirmation prompt"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Remove one fingerprint (admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    fingerprint = _fingerprint_credential(fingerprint_id)
    key = _resolve_key(target)
    if not yes:
        typer.confirm(
            f"Remove fingerprint {fingerprint_id} from {key.lockAlias or key.lockMac}?",
            abort=True,
        )
    _run_credential_command(_run_delete_fingerprint(key, fingerprint))
    typer.echo(f"✓ fingerprint {fingerprint_id} removed")


@app.command("clear-fingerprints")
def clear_fingerprints(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    yes: bool = typer.Option(False, "--yes", "-y", help="skip the confirmation prompt"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Remove EVERY fingerprint from the lock - no undo (admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    key = _resolve_key(target)
    if not yes:
        typer.confirm(
            f"This removes EVERY fingerprint from {key.lockAlias or key.lockMac}, "
            "not just one. Continue?",
            abort=True,
        )
    _run_credential_command(_run_clear_fingerprints(key))
    typer.echo("✓ all fingerprints cleared")


async def _run_unlock(key: VirtualKey) -> None:
    async with TTLockClient(key) as c:
        await c.unlock()


async def _run_lock(key: VirtualKey) -> None:
    async with TTLockClient(key) as c:
        await c.lock()


async def _run_state(key: VirtualKey) -> tuple[LockState | None, int | None]:
    async with TTLockClient(key) as c:
        return await c.query_state()


async def _run_sound(key: VirtualKey, *, enabled: bool) -> None:
    async with TTLockClient(key) as c:
        await c.set_lock_sound(enabled=enabled)


async def _run_volume(key: VirtualKey, level: int) -> None:
    async with TTLockClient(key) as c:
        await c.set_lock_volume(level)


async def _run_get_sound(key: VirtualKey) -> LockSound:
    async with TTLockClient(key) as c:
        return await c.get_lock_sound()


async def _run_device_info(key: VirtualKey) -> DeviceInfo:
    async with TTLockClient(key) as c:
        return await c.get_device_info()


async def _run_features(key: VirtualKey) -> DeviceFeatures:
    async with TTLockClient(key) as c:
        return await c.get_device_features()


async def _run_get_device_properties(key: VirtualKey) -> DeviceProperties:
    async with TTLockClient(key) as c:
        return await c.get_device_properties()


async def _run_add_passcode(key: VirtualKey, code: str, validity: Validity) -> None:
    async with TTLockClient(key) as c:
        await c.passcodes.add(code, validity)


async def _run_modify_passcode(
    key: VirtualKey, code: str, new_code: str | None, validity: Period | None
) -> None:
    async with TTLockClient(key) as c:
        await c.passcodes.modify(code, new_code=new_code, validity=validity)


async def _run_enroll_card(key: VirtualKey, validity: Validity, wait_seconds: float) -> Credential:
    def report(step: CardEnrollmentStep) -> None:
        if step == CardEnrollmentStep.WAITING_FOR_CARD:
            typer.echo(f"Present the card to the lock now (waiting up to {wait_seconds:g} s)...")

    async with TTLockClient(key) as c:
        return await c.cards.enroll(validity, report, timeout=wait_seconds)


async def _run_add_card(key: VirtualKey, card: Credential, validity: Validity) -> None:
    async with TTLockClient(key) as c:
        await c.cards.add(card, validity)


async def _run_modify_card(key: VirtualKey, card: Credential, validity: Validity) -> None:
    async with TTLockClient(key) as c:
        await c.cards.modify(card, validity)


async def _run_delete_card(key: VirtualKey, card: Credential) -> None:
    async with TTLockClient(key) as c:
        await c.cards.delete(card)


async def _run_clear_cards(key: VirtualKey) -> None:
    async with TTLockClient(key) as c:
        await c.cards.clear()


async def _run_enroll_fingerprint(
    key: VirtualKey, validity: Validity, wait_seconds: float
) -> Credential:
    def report(progress: FingerprintEnrollmentProgress) -> None:
        if progress.step == FingerprintEnrollmentStep.WAITING_FOR_FINGER:
            typer.echo(
                f"Touch the lock's sensor with the finger now; {progress.touches_required} "
                "touches are needed..."
            )
        elif progress.step == FingerprintEnrollmentStep.TOUCH_RECORDED:
            typer.echo(f"touch {progress.touches_recorded}/{progress.touches_required}")

    async with TTLockClient(key) as c:
        return await c.fingerprints.enroll(validity, report, timeout=wait_seconds)


async def _run_modify_fingerprint(
    key: VirtualKey, fingerprint: Credential, validity: Validity
) -> None:
    async with TTLockClient(key) as c:
        await c.fingerprints.modify(fingerprint, validity)


async def _run_delete_fingerprint(key: VirtualKey, fingerprint: Credential) -> None:
    async with TTLockClient(key) as c:
        await c.fingerprints.delete(fingerprint)


async def _run_clear_fingerprints(key: VirtualKey) -> None:
    async with TTLockClient(key) as c:
        await c.fingerprints.clear()


async def _run_get_admin_passcode(key: VirtualKey) -> str:
    async with TTLockClient(key) as c:
        return await c.admin_passcode.get()


async def _run_set_admin_passcode(key: VirtualKey, code: str) -> None:
    async with TTLockClient(key) as c:
        await c.admin_passcode.set(code)


async def _run_get_schedule(key: VirtualKey, credential: Credential) -> tuple[WeeklyWindow, ...]:
    async with TTLockClient(key) as c:
        return await c.weekly_schedules.get(credential)


async def _run_set_schedule(
    key: VirtualKey, credential: Credential, windows: tuple[WeeklyWindow, ...]
) -> None:
    async with TTLockClient(key) as c:
        listed: list[CardEntry] | list[FingerprintEntry] = (
            await c.get_cards()
            if credential.credential_type == CredentialType.CARD
            else await c.get_fingerprints()
        )
        if credential not in {Credential.of(entry) for entry in listed}:
            raise typer.BadParameter(f"the lock does not hold {_describe(credential)}")
        await c.weekly_schedules.set(credential, windows)


async def _run_clear_schedule(key: VirtualKey, credential: Credential) -> None:
    async with TTLockClient(key) as c:
        await c.weekly_schedules.clear(credential)


async def _run_delete_passcode(key: VirtualKey, code: str) -> None:
    async with TTLockClient(key) as c:
        await c.passcodes.delete(code)


async def _run_clear_passcodes(key: VirtualKey) -> None:
    async with TTLockClient(key) as c:
        await c.clear_passcodes()


async def _run_get_passcodes(key: VirtualKey) -> list[PasscodeEntry]:
    async with TTLockClient(key) as c:
        return await c.get_passcodes()


async def _run_get_auto_lock(key: VirtualKey) -> int:
    async with TTLockClient(key) as c:
        return await c.get_auto_lock_time()


async def _run_set_auto_lock(key: VirtualKey, seconds: int) -> None:
    async with TTLockClient(key) as c:
        await c.set_auto_lock_time(seconds)


async def _run_get_auto_lock_limits(key: VirtualKey) -> AutoLockLimits:
    async with TTLockClient(key) as c:
        return await c.get_auto_lock_limits()


async def _run_get_fingerprints(key: VirtualKey) -> list[FingerprintEntry]:
    async with TTLockClient(key) as c:
        return await c.get_fingerprints()


async def _run_get_cards(key: VirtualKey) -> list[CardEntry]:
    async with TTLockClient(key) as c:
        return await c.get_cards()


if (
    __name__ == "__main__"
):  # pragma: no cover  -- module entry point, exercised via the `ttlock` console script
    app()
