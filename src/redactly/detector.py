from __future__ import annotations

from collections.abc import Callable
from typing import Any

import regex as re

from .config import get_config
from .detectors import (
    BUILTIN_PATTERNS,
    CompiledPattern,
    EntropyDetector,
    compile_patterns,
    is_sensitive_key,
)
from .rules import DetectionType, Hit, Rule

ExtraDetector = Callable[[str], list[Hit]]
_extra_detectors: list[ExtraDetector] = []
_all_patterns: tuple[CompiledPattern, ...] = BUILTIN_PATTERNS
_entropy_detector: EntropyDetector | None = None

_TOKEN_RE = re.compile(r"\S+")


def _rebuild_custom_patterns(rules: list[Rule]) -> None:
    global _all_patterns
    _all_patterns = BUILTIN_PATTERNS + compile_patterns([(r.pattern, r.type) for r in rules])


def _rebuild_entropy_detector(threshold: float, min_length: int, enabled: bool) -> None:
    global _entropy_detector
    _entropy_detector = (
        EntropyDetector(threshold=threshold, min_length=min_length) if enabled else None
    )


def add_detector(fn: ExtraDetector) -> None:
    """Register an additional detector. Runs after built-ins on every string scan."""
    _extra_detectors.append(fn)


def _clear_extra_detectors() -> None:
    _extra_detectors.clear()


def _scan_string(
    value: str,
    *,
    key_path: tuple[str | int, ...] = (),
    force_secret: bool = False,
) -> list[Hit]:
    cfg = get_config()
    hits: list[Hit] = []

    if force_secret and value:
        hits.append(
            Hit(
                type=DetectionType.SECRET,
                value=value,
                start=0,
                end=len(value),
                key_path=key_path,
                detector="key_based",
            )
        )
        return hits

    for cp in _all_patterns:
        if cp.type == DetectionType.EMAIL and not cfg.mask_emails:
            continue
        if cp.type == DetectionType.PHONE and not cfg.mask_phones:
            continue
        for m in cp.pattern.finditer(value):
            start, end = m.span(cp.value_group)
            if start < 0:  # pragma: no cover
                continue
            matched = value[start:end]
            if not matched:  # pragma: no cover
                continue
            hits.append(
                Hit(
                    type=cp.type,
                    value=matched,
                    start=start,
                    end=end,
                    key_path=key_path,
                    detector=cp.name,
                )
            )

    if _entropy_detector is not None:
        det = _entropy_detector
        for m in _TOKEN_RE.finditer(value):
            token = m.group(0)
            start, end = m.span()
            if det.is_high_entropy(token) and not _overlaps_existing(hits, start, end):
                hits.append(
                    Hit(
                        type=DetectionType.ENTROPY,
                        value=token,
                        start=start,
                        end=end,
                        key_path=key_path,
                        detector="entropy",
                    )
                )

    for fn in _extra_detectors:
        hits.extend(fn(value))

    return hits


def _overlaps_existing(hits: list[Hit], start: int, end: int) -> bool:
    return any(h.start < end and start < h.end for h in hits)


def scan_mapping(obj: Any, key_path: tuple[str | int, ...] = ()) -> list[Hit]:
    hits: list[Hit] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            sub_path = (*key_path, str(k))
            if isinstance(v, str):
                hits.extend(
                    _scan_string(v, key_path=sub_path, force_secret=is_sensitive_key(str(k)))
                )
            elif isinstance(v, (dict, list, tuple)):
                hits.extend(scan_mapping(v, sub_path))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            sub_path = (*key_path, i)
            if isinstance(v, str):
                hits.extend(_scan_string(v, key_path=sub_path))
            elif isinstance(v, (dict, list, tuple)):
                hits.extend(scan_mapping(v, sub_path))
    return hits


def scan_string(value: str) -> list[Hit]:
    return _scan_string(value)
