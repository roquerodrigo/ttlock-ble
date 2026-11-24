"""Validity: when a credential is accepted.

Passcodes take every form (`PasscodeManager.add`); cards take `Permanent`,
`Period` and `Weekly` (`CardManager`), and fingerprints will take the same.
"""

from __future__ import annotations

from .period import Period
from .permanent import Permanent
from .single_use import SingleUse
from .weekly import Weekly
from .weekly_window import WeeklyWindow

type Validity = Permanent | Period | SingleUse | Weekly

__all__ = ["Period", "Permanent", "SingleUse", "Validity", "Weekly", "WeeklyWindow"]
