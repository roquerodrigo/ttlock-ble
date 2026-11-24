"""Validity: when a credential is accepted, shared by passcodes, cards and fingerprints."""

from __future__ import annotations

from .period import Period
from .permanent import Permanent
from .single_use import SingleUse
from .weekly import Weekly
from .weekly_window import WeeklyWindow

type Validity = Permanent | Period | SingleUse | Weekly

__all__ = ["Period", "Permanent", "SingleUse", "Validity", "Weekly", "WeeklyWindow"]
