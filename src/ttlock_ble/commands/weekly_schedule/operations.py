"""Operation bytes of the weekly-schedule command (CMD 0x70) this codec is allowed to send.

Only the operations seen in the official app's own traffic are defined.
Operation 3 (REMOVE) and operation 5 are deliberately absent: operation 5
disconnected the lock during earlier probing and operation 3's layout is
unknown. They must never become sendable through this package, so no
public builder takes an operation parameter - see
`tests/test_weekly_schedule.py::test_forbidden_operations_are_unreachable`.
"""

from __future__ import annotations

QUERY_OPERATION = 0x01
ADD_OPERATION = 0x02
CLEAR_OPERATION = 0x04
