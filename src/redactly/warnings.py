from __future__ import annotations

import contextlib
import os
import sys
import time
from typing import Any

from .config import get_config
from .rules import Action, Hit

_ACTION_LABELS: dict[Action, str] = {
    Action.MASK: "MASKED",
    Action.BLOCK: "BLOCKED",
    Action.ALLOW: "ALLOWED",
}


def emit(hit: Hit, *, action: Action, pathname: str, lineno: int) -> None:
    """Print a developer-facing warning to stderr and forward to telemetry hook."""
    cfg = get_config()
    location = f"{os.path.basename(pathname)}:{lineno}"
    action_label = _ACTION_LABELS[action]

    if cfg.dev_warnings:
        print(
            "[REDACTLY WARNING]\n"
            f"Type: {hit.type.value}\n"
            f"Key: {hit.key or '<message>'}\n"
            f"Location: {location}\n"
            f"Action: {action_label}\n",
            file=sys.stderr,
            flush=True,
        )

    if cfg.telemetry_hook is not None:
        event: dict[str, Any] = {
            "type": hit.type.value,
            "action": action_label.lower(),
            "key": hit.key,
            "source": location,
            "detector": hit.detector,
            "timestamp": time.time(),
        }
        with contextlib.suppress(Exception):
            cfg.telemetry_hook(event)
