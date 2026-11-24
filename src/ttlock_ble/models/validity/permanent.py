"""Permanent: a credential valid at any time, with no expiry."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Permanent:
    """Valid at any time, with no start and no expiry."""
