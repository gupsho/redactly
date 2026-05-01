from __future__ import annotations

SENSITIVE_KEY_FRAGMENTS: tuple[str, ...] = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "auth",
    "api_key",
    "apikey",
    "access_key",
    "accesskey",
    "credential",
    "private_key",
    "session",
    "cookie",
)


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(fragment in lowered for fragment in SENSITIVE_KEY_FRAGMENTS)
