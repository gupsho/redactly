"""redactly — safe logging SDK that prevents accidental PII/secret leakage."""

from __future__ import annotations

from .config import configure, get_config, reset_config
from .detector import add_detector
from .exceptions import RedactlyBlockedError, RedactlyError
from .logger import get_logger
from .masker import add_masker
from .rules import Action, DetectionType, Hit, MaskStyle, Rule

__all__ = [
    "Action",
    "DetectionType",
    "Hit",
    "MaskStyle",
    "RedactlyBlockedError",
    "RedactlyError",
    "Rule",
    "add_detector",
    "add_masker",
    "configure",
    "get_config",
    "get_logger",
    "reset_config",
]

__version__ = "0.1.1"
