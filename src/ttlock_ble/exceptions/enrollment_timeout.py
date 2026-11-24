"""EnrollmentTimeoutError: nobody presented a card while the lock was waiting for one."""

from __future__ import annotations

from .reply_timeout import ReplyTimeoutError


class EnrollmentTimeoutError(ReplyTimeoutError):
    """Raised when the lock reported it was waiting for a card and none was presented in time.

    The lock sends nothing when its own wait ends, so the SDK's timeout is the
    only signal. `CardManager.enroll` raises this only after its safety window,
    when the lock has most likely left add mode: on an SN484_PV53 lock the
    window is about 10-20 s long (other models: not tested).
    """
