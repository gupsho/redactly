from __future__ import annotations


class RedactlyError(Exception):
    """Base class for all redactly errors."""


class RedactlyBlockedError(RedactlyError):
    """Raised when a log call is blocked because it contains sensitive data
    and the active policy resolves that hit to the BLOCK action.

    The log record is discarded — nothing reaches the handlers.
    """

    def __init__(self, hit_type: str, key: str | None, location: str) -> None:
        self.hit_type = hit_type
        self.key = key
        self.location = location
        msg = f"Redactly blocked log at {location}: type={hit_type} key={key or '<message>'}"
        super().__init__(msg)
