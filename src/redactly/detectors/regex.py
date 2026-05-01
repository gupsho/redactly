from __future__ import annotations

from dataclasses import dataclass

import regex as re

from ..rules import DetectionType


@dataclass(frozen=True, slots=True)
class CompiledPattern:
    name: str
    type: DetectionType
    pattern: re.Pattern[str]
    # If the match has a capturing group, mask only that group instead of the
    # whole match. Useful for things like `token=abc123` where we want to keep
    # the `token=` prefix visible.
    value_group: int = 0


def _compile(expr: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(expr, flags)


BUILTIN_PATTERNS: tuple[CompiledPattern, ...] = (
    CompiledPattern(
        name="email",
        type=DetectionType.EMAIL,
        pattern=_compile(
            r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
        ),
    ),
    CompiledPattern(
        name="aws_access_key",
        type=DetectionType.AWS_KEY,
        pattern=_compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    CompiledPattern(
        name="stripe_key",
        type=DetectionType.SECRET,
        pattern=_compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b"),
    ),
    CompiledPattern(
        name="github_token",
        type=DetectionType.SECRET,
        pattern=_compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    ),
    CompiledPattern(
        name="jwt",
        type=DetectionType.TOKEN,
        pattern=_compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
    ),
    CompiledPattern(
        name="bearer_token",
        type=DetectionType.TOKEN,
        pattern=_compile(
            r"(?i)\b(?:bearer|token|api[_\-]?key|authorization)"
            r"[=:\s\"']+([A-Za-z0-9_\-\.]{16,})",
        ),
        value_group=1,
    ),
    CompiledPattern(
        name="phone",
        type=DetectionType.PHONE,
        # E.164-ish: optional +, 8–15 digits, permissive separators.
        pattern=_compile(r"(?<!\w)\+?\d[\d\s().\-]{7,16}\d(?!\w)"),
    ),
)


def compile_patterns(extra: list[tuple[str, DetectionType]]) -> tuple[CompiledPattern, ...]:
    """Compile a list of (pattern_string, type) into CompiledPattern tuples."""
    return tuple(
        CompiledPattern(name=f"custom_{i}", type=t, pattern=_compile(p))
        for i, (p, t) in enumerate(extra)
    )
