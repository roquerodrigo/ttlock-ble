"""CloudCredentials: identity returned from a successful /user/login."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CloudCredentials:
    """Per-user TTLock cloud session, captured after `/user/login` succeeds."""

    uid: int
    access_token: str
    username: str
