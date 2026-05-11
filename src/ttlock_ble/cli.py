"""Typer-powered `ttlock` CLI: sync, verify, list, unlock, lock, state, battery."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
from pathlib import Path

import typer
from dotenv import load_dotenv

from ._cloud_helpers import ERR_NEW_DEVICE_LOGIN
from .client import TTLockClient
from .cloud import TTLockCloud
from .exceptions import CloudError
from .models import VirtualKey

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
    label = {0: "LOCKED", 1: "UNLOCKED"}.get(s, "UNKNOWN")
    batt_str = f"{batt}%" if batt is not None else "?"
    typer.echo(f"state: {label} ({s})  battery: {batt_str}")


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


async def _run_unlock(key: VirtualKey) -> None:
    async with TTLockClient(key) as c:
        await c.unlock()


async def _run_lock(key: VirtualKey) -> None:
    async with TTLockClient(key) as c:
        await c.lock()


async def _run_state(key: VirtualKey) -> tuple[int, int | None]:
    async with TTLockClient(key) as c:
        return await c.query_state()


if __name__ == "__main__":
    app()
