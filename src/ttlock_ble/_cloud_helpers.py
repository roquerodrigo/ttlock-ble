"""Internal helpers shared by the cloud client (signing, defaults, state path)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

DEFAULT_APP_ID = "9aa8af853eea43fa839a0a474ee9d8ab"
DEFAULT_APP_SECRET = "07752080e28d43e5f8a7cdb8aad3c0c3"  # noqa: S105  -- public OEM secret embedded in the DLock-XP APK
DEFAULT_BASE_URL = "https://servlet.ttlock.com"
DEFAULT_PACKAGE = "com.dlock.smart"

ERR_NEW_DEVICE_LOGIN = -1014

CODE_TYPE_NEW_DEVICE_LOGIN = 4
CODE_TYPE_DELETE_ACCOUNT = 10
CODE_CHANNEL_DEFAULT = 1


def state_dir() -> Path:
    """Where the local key cache + persistent uniqueid live (defaults to `~/.ttlock/`)."""
    p = Path(os.environ.get("TTLOCK_KEY_STORE", "~/.ttlock/keys.json")).expanduser().parent
    p.mkdir(parents=True, exist_ok=True)
    return p


def load_uniqueid() -> str:
    """Return the persistent install identifier, generating one on first call.

    Persisted across runs so the cloud doesn't trigger new-device validation
    on every login.
    """
    f = state_dir() / "uniqueid"
    if f.exists():
        return f.read_text().strip()
    new = uuid.uuid4().hex
    f.write_text(new)
    return new


def md5_hex(s: str) -> str:
    """MD5-then-hex of a UTF-8 string (used to hash passwords for /user/login)."""
    return hashlib.md5(s.encode("utf-8"), usedforsecurity=False).hexdigest()


def sign_request(app_id: str, app_secret: str, path: str, params: Mapping[str, str]) -> str:
    """HMAC-SHA256 signature the TTLock cloud expects on every request.

    Mirrors `com.lzy.okhttputils.utils.ScienerSignatureUtil.getSignature`:

        msg = path + "?" + sorted(k=v).join("&") + appId
        signature = base64( HMAC-SHA256(key=appSecret, msg) )
    """
    items = sorted((str(k), str(v)) for k, v in params.items())
    msg = path + "?" + "&".join(f"{k}={v}" for k, v in items) + app_id
    digest = hmac.new(app_secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")
