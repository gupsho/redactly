from __future__ import annotations

import os
import threading
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .rules import Action, MaskStyle, Rule

TelemetryHook = Callable[[dict[str, Any]], None]

_TRUTHY = frozenset({"1", "true", "yes", "on"})


class Config(BaseModel):
    """Global redactly configuration."""

    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=False, extra="forbid")

    enabled: bool = True
    default_policy: Action = Action.MASK
    block_secrets: bool = False
    mask_emails: bool = True
    mask_phones: bool = True
    dev_warnings: bool = True
    entropy: bool = False
    entropy_threshold: float = Field(default=4.5, ge=0.0, le=8.0)
    entropy_min_length: int = Field(default=20, ge=8)
    mask_style: MaskStyle = MaskStyle.FORMAT_PRESERVING
    custom_rules: list[Rule] = Field(default_factory=list)
    telemetry_hook: TelemetryHook | None = None

    def is_enabled(self) -> bool:
        if os.environ.get("REDACTLY_DISABLED", "").strip().lower() in _TRUTHY:
            return False
        return self.enabled


_config_lock = threading.Lock()
_config: Config = Config()


def configure(**kwargs: Any) -> Config:
    """Replace the process-global config with one merged from kwargs."""
    global _config
    with _config_lock:
        _config = Config(**{**_config.model_dump(), **kwargs})
        _apply_side_effects(_config)
        return _config


def get_config() -> Config:
    return _config


def reset_config() -> None:
    global _config
    with _config_lock:
        _config = Config()
        _apply_side_effects(_config)


def _apply_side_effects(cfg: Config) -> None:
    from . import detector as _detector

    _detector._rebuild_custom_patterns(cfg.custom_rules)
    _detector._rebuild_entropy_detector(cfg.entropy_threshold, cfg.entropy_min_length, cfg.entropy)
