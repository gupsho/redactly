from __future__ import annotations

import math
from collections import Counter

_ENTROPY_CHARSET = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=_-")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def looks_like_secret_charset(s: str) -> bool:
    return bool(s) and set(s).issubset(_ENTROPY_CHARSET)
