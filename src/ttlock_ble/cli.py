"""Typer-powered `ttlock` CLI: locks, state, sound, passcodes, auto-lock, fingerprints."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

import typer
from dotenv import load_dotenv

from ._cloud_helpers import ERR_NEW_DEVICE_LOGIN
from .client import TTLockClient
from .cloud import TTLockCloud
from .constants import LockVolume
from .exceptions import CloudError
from .models import AutoLockLimits, DeviceInfo, FingerprintEntry, VirtualKey

if TYPE_CHECKING:
    from .constants import LockState

app = typer.Typer(add_completion=False, help="DLock-XP / TTLock BLE control")
KEY_STORE = Path(os.environ.get("TTLOCK_KEY_STORE", "~/.ttlock/keys.json")).expanduser()


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


@app.command()
def sync(verbose: bool = typer.Option(False, "-v", help="HTTP debug logs")) -> None:
    """Log in to the TTLock cloud and cache the user's eKeys locally."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    email, password = _load_env()
    keys = asyncio.run(_run_sync(email, password))
    KEY_STORE.parent.mkdir(parents=True, exist_ok=True)
    KEY_STORE.write_text(json.dumps([k.to_dict() for k in keys], indent=2))
    typer.echo(f"saved → {KEY_STORE}")


@app.command()
def verify(
    code: str = typer.Argument(..., help="Verification code from email/SMS"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Register this machine with TTLock using the verification code."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    email, _ = _load_env()
    asyncio.run(_run_verify(email, code))
    typer.echo("✓ device registered. Now run `ttlock sync`.")


async def _run_sync(email: str, password: str) -> list[VirtualKey]:
    async with TTLockCloud() as cloud:
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


async def _run_verify(email: str, code: str) -> None:
    async with TTLockCloud() as cloud:
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


@app.command("add-passcode")
def add_passcode(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    code: str = typer.Argument(..., help="4-9 digit passcode"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Provision a keypad passcode (requires an admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    key = _resolve_key(target)
    asyncio.run(_run_add_passcode(key, code))
    typer.echo(f"✓ passcode {code} added")


@app.command("delete-passcode")
def delete_passcode(
    target: str = typer.Argument(..., help="lockId, alias, or MAC"),
    code: str = typer.Argument(..., help="passcode to remove"),
    verbose: bool = typer.Option(False, "-v"),
) -> None:
    """Remove a keypad passcode previously added via add-passcode (requires an admin eKey)."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
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
        typer.echo(f"  slot={entry.slot:<3} fp_id={entry.fp_id.hex()}  start={start}  end={end}")
    typer.echo(
        "note: this cannot detect cyclic (day-of-week/time-range) restrictions - "
        "a fingerprint above may still be limited to specific days/hours."
    )


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


async def _run_device_info(key: VirtualKey) -> DeviceInfo:
    async with TTLockClient(key) as c:
        return await c.get_device_info()


async def _run_add_passcode(key: VirtualKey, code: str) -> None:
    async with TTLockClient(key) as c:
        await c.add_passcode(code)


async def _run_delete_passcode(key: VirtualKey, code: str) -> None:
    async with TTLockClient(key) as c:
        await c.delete_passcode(code)


async def _run_clear_passcodes(key: VirtualKey) -> None:
    async with TTLockClient(key) as c:
        await c.clear_passcodes()


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


if (
    __name__ == "__main__"
):  # pragma: no cover  -- module entry point, exercised via the `ttlock` console script
    app()
