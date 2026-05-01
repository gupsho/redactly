from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class DetectionType(StrEnum):
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    SECRET = "SECRET"
    TOKEN = "TOKEN"
    AWS_KEY = "AWS_KEY"
    ENTROPY = "ENTROPY"
    CUSTOM = "CUSTOM"
    PII = "PII"


class Action(StrEnum):
    MASK = "mask"
    BLOCK = "block"
    ALLOW = "allow"


class MaskStyle(StrEnum):
    FORMAT_PRESERVING = "format_preserving"
    FULL_REDACTION = "full_redaction"


@dataclass(frozen=True, slots=True)
class Rule:
    """A custom detection rule provided via configure(custom_rules=[...])."""

    pattern: str
    type: DetectionType = DetectionType.CUSTOM
    action: Action = Action.MASK


@dataclass(frozen=True, slots=True)
class Hit:
    """A single detection result."""

    type: DetectionType
    value: str
    start: int
    end: int
    key_path: tuple[str | int, ...] = field(default_factory=tuple)
    detector: str = ""

    @property
    def key(self) -> str | None:
        return str(self.key_path[-1]) if self.key_path else None
