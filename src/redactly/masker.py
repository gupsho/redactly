from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .config import get_config
from .rules import DetectionType, Hit, MaskStyle

ExtraMasker = Callable[[Hit], str | None]
_extra_maskers: list[ExtraMasker] = []


def add_masker(fn: ExtraMasker) -> None:
    """Register an additional masker. Runs before built-in masking; if it returns
    a non-None string that becomes the masked value.
    """
    _extra_maskers.append(fn)


def _clear_extra_maskers() -> None:
    _extra_maskers.clear()


def _mask_email(v: str) -> str:
    local, _, domain = v.partition("@")
    if not domain:
        return "*" * len(v)
    if len(local) <= 1:
        return f"{local}***@{domain}"
    return f"{local[0]}***@{domain}"


def _mask_phone(v: str) -> str:
    digits_only = "".join(ch for ch in v if ch.isdigit())
    if len(digits_only) <= 4:
        return "*" * len(v)
    first, last = digits_only[:2], digits_only[-2:]
    stars = "*" * (len(digits_only) - 4)
    return f"{first}{stars}{last}"


def _mask_token(v: str) -> str:
    if len(v) < 8:
        return _mask_generic(v)
    # Keep a short type-indicating prefix (e.g. `sk_live_`, `ghp_`) + last 3 chars.
    # We look only inside the first 9 characters so that structurally-different
    # tokens (JWT, base64 blobs, opaque random strings) cannot leak large
    # internal segments through a deep underscore.
    head = v[:9]
    last_underscore = head.rfind("_")
    prefix = head[: last_underscore + 1] if last_underscore >= 0 else v[:2]
    return f"{prefix}****{v[-3:]}"


def _mask_generic(v: str) -> str:
    if len(v) <= 2:
        return "*" * len(v)
    return f"{v[0]}{'*' * (len(v) - 2)}{v[-1]}"


def _format_preserving(hit: Hit) -> str:
    t = hit.type
    v = hit.value
    if t == DetectionType.EMAIL:
        return _mask_email(v)
    if t == DetectionType.PHONE:
        return _mask_phone(v)
    if t in {DetectionType.SECRET, DetectionType.TOKEN, DetectionType.AWS_KEY}:
        return _mask_token(v)
    return _mask_generic(v)


def mask_value(hit: Hit) -> str:
    """Return the masked replacement string for a single hit."""
    for fn in _extra_maskers:
        result = fn(hit)
        if result is not None:
            return result
    if get_config().mask_style == MaskStyle.FULL_REDACTION:
        return f"[REDACTED_{hit.type.value}]"
    return _format_preserving(hit)


def apply_to_string(value: str, hits: list[Hit]) -> str:
    """Replace each hit span in `value` with its masked form."""
    if not hits:
        return value
    ordered = sorted(hits, key=lambda h: h.start, reverse=True)
    out = value
    for h in ordered:
        out = out[: h.start] + mask_value(h) + out[h.end :]
    return out


def apply_to_structure(obj: Any, hits: list[Hit]) -> Any:
    """Apply hits to a mutable deep-copy of a structured payload. Mutates in place."""
    by_parent: dict[tuple[str | int, ...], list[Hit]] = {}
    for h in hits:
        if not h.key_path:  # pragma: no cover
            continue
        by_parent.setdefault(h.key_path[:-1], []).append(h)

    for parent_path, group in by_parent.items():
        container = _resolve_path(obj, parent_path)
        if container is None:  # pragma: no cover
            continue
        per_leaf: dict[str | int, list[Hit]] = {}
        for h in group:
            per_leaf.setdefault(h.key_path[-1], []).append(h)
        for leaf, leaf_hits in per_leaf.items():
            _mask_leaf(container, leaf, leaf_hits)
    return obj


def _mask_leaf(container: Any, leaf: str | int, leaf_hits: list[Hit]) -> None:
    if isinstance(container, tuple):  # pragma: no cover — immutable
        return
    real_key = _resolve_key(container, leaf)
    if real_key is None:  # pragma: no cover
        return
    current = container[real_key]
    if not isinstance(current, str):  # pragma: no cover
        return
    whole = next((h for h in leaf_hits if h.start == 0 and h.end == len(current)), None)
    new_val = mask_value(whole) if whole is not None else apply_to_string(current, leaf_hits)
    container[real_key] = new_val


def _resolve_path(obj: Any, path: tuple[str | int, ...]) -> Any:
    cur = obj
    for key in path:
        real = _resolve_key(cur, key)
        if real is None:  # pragma: no cover
            return None
        cur = cur[real]
    return cur


def _resolve_key(container: Any, key: str | int) -> Any:
    """Return the real key/index usable with container[...] — or None if missing."""
    if isinstance(container, dict):
        if key in container:
            return key
        for k in container:
            if str(k) == str(key):
                return k
        return None  # pragma: no cover
    if isinstance(container, (list, tuple)) and isinstance(key, int) and 0 <= key < len(container):
        return key
    return None  # pragma: no cover
