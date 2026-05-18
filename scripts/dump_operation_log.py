#!/usr/bin/env python3
"""Pull the on-device operation log over BLE and write each record to a file.

Reads a cached eKey from `~/.ttlock/keys.json` (override with
`TTLOCK_KEY_STORE`) — populate it first with `ttlock sync`. The lock
must be in BLE range and awake; touch the keypad if needed.

By default the records are written to
`operation_log_<mac>_<timestamp>.txt` in the current working directory;
pass `-o PATH` to choose a different location (use `-o -` to stream
records to stdout instead).

Usage:
    uv run python scripts/dump_operation_log.py            # first key in the store
    uv run python scripts/dump_operation_log.py 20035518   # by lockId / alias / MAC
    uv run python scripts/dump_operation_log.py -n 20      # cap to 20 records
    uv run python scripts/dump_operation_log.py -o out.txt # custom output file
    uv run python scripts/dump_operation_log.py -o -       # stream to stdout
    uv run python scripts/dump_operation_log.py -v         # debug logs (BLE traffic)
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
import logging
import os
import sys
from pathlib import Path

from ttlock_ble import TTLockClient, VirtualKey
from ttlock_ble.constants import LogOperate
from ttlock_ble.models import LogEntry

KEY_STORE = Path(os.environ.get("TTLOCK_KEY_STORE", "~/.ttlock/keys.json")).expanduser()


def _load_keys() -> list[VirtualKey]:
    if not KEY_STORE.exists():
        sys.exit(f"no keys cached at {KEY_STORE} — run `ttlock sync` first")
    return [VirtualKey.from_dict(d) for d in json.loads(KEY_STORE.read_text())]


def _resolve(target: str | None) -> VirtualKey:
    keys = _load_keys()
    if target is None:
        return keys[0]
    for k in keys:
        if str(k.lockId) == target or k.lockAlias == target or k.lockMac.upper() == target.upper():
            return k
    sys.exit(
        f"no key matches '{target}'. available: "
        + ", ".join(f"{k.lockId}({k.lockAlias})" for k in keys)
    )


def _format(entry: LogEntry) -> str:
    when = entry.operate_date.strftime("%Y-%m-%d %H:%M:%S") if entry.operate_date else "?"
    label = (
        entry.record_type.name
        if isinstance(entry.record_type, LogOperate)
        else f"UNKNOWN({entry.record_type})"
    )
    parts = [
        f"#{entry.record_number:>5}",
        when,
        f"batt={entry.lock_battery:>3}%",
        label,
    ]
    if entry.uid is not None:
        parts.append(f"uid={entry.uid}")
    if entry.record_id is not None:
        parts.append(f"rid={entry.record_id}")
    if entry.password is not None:
        parts.append(f"pwd/id={entry.password}")
    if entry.new_password:
        parts.append(f"new={entry.new_password}")
    if entry.key_id is not None:
        parts.append(f"key={entry.key_id}")
    if entry.accessory_battery is not None:
        parts.append(f"acc_batt={entry.accessory_battery}%")
    if entry.delete_date:
        parts.append(f"deleted_at={entry.delete_date.strftime('%Y-%m-%d %H:%M')}")
    return "  ".join(parts)


def _default_output_path(key: VirtualKey) -> Path:
    stamp = dt.datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    mac = key.lockMac.replace(":", "").lower()
    return Path.cwd() / f"operation_log_{mac}_{stamp}.txt"


async def _run(
    key: VirtualKey,
    max_entries: int | None,
    scan_timeout: float,
    from_sequence: int,
) -> list[LogEntry]:
    print(f"connecting to {key.lockAlias or key.lockName} ({key.lockMac})…")
    async with TTLockClient(key, scan_timeout=scan_timeout) as client:
        print("connected — pulling operation log (this can take a while)…")
        return await client.get_operation_log(max_entries=max_entries, from_sequence=from_sequence)


def _render(key: VirtualKey, entries: list[LogEntry], from_sequence: int) -> str:
    header = (
        f"# operation log for {key.lockAlias or key.lockName} ({key.lockMac})\n"
        f"# fetched {dt.datetime.now().astimezone().isoformat(timespec='seconds')}  "
        f"records={len(entries)}  from_sequence={from_sequence}\n"
    )
    body = "\n".join(_format(e) for e in entries) + ("\n" if entries else "")
    return header + body


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "target", nargs="?", help="lockId, alias, or MAC (default: first cached key)"
    )
    parser.add_argument(
        "-n", "--max-entries", type=int, default=None, help="cap on records returned"
    )
    parser.add_argument(
        "-s", "--scan-timeout", type=float, default=60.0, help="BLE scan window in seconds"
    )
    parser.add_argument(
        "-f",
        "--from-sequence",
        type=lambda v: int(v, 0),
        default=0xFFFF,
        help="initial cursor (0xFFFF = since last sync; set lower to re-fetch history)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="output file path (default: ./operation_log_<mac>_<ts>.txt; '-' = stdout)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="DEBUG logs (BLE traffic)")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    key = _resolve(args.target)
    if args.output == "-":
        out_path: Path | None = None
    elif args.output is None:
        out_path = _default_output_path(key)
    else:
        out_path = Path(args.output).expanduser().resolve()

    entries = asyncio.run(_run(key, args.max_entries, args.scan_timeout, args.from_sequence))
    text = _render(key, entries, args.from_sequence)
    if out_path is None:
        sys.stdout.write(text)
        return
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text)
    print(f"\nwrote {len(entries)} record(s) → {out_path}")


if __name__ == "__main__":
    main()
