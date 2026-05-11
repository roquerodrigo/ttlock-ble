# ttlock-ble

Python SDK for controlling **DLock-XP / TTLock** Bluetooth smart locks
without depending on the TTLock cloud at unlock time. The session AES key
is downloaded once from the TTLock cloud and cached locally; from then on
all lock/unlock/state operations run fully offline over BLE.

## Always read `CODE_STYLE.md` first

Before creating, renaming or restructuring any file/class/function, **read
[`CODE_STYLE.md`](./CODE_STYLE.md)**. It is the single source of truth for
conventions: language, file organisation, naming, typing, imports,
docstrings, comments, logging, error messages, public API surface,
pre-commit hooks, conventional commits, packaging, releasing, testing,
lint workflow.

## Verification workflow

After every code change, always run lint then tests, in that order, before
declaring the task done:

```bash
uv run ruff format . && uv run ruff check . --fix && uv run mypy src
uv run pytest
```

Both gates mirror CI. Skip this only when the change literally cannot
affect lint or tests (e.g., README-only edits).
