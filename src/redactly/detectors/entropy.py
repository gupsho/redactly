from __future__ import annotations

from dataclasses import dataclass

from ..utils import looks_like_secret_charset, shannon_entropy


@dataclass(frozen=True, slots=True)
class EntropyDetector:
    threshold: float
    min_length: int

    def is_high_entropy(self, value: str) -> bool:
        if len(value) < self.min_length:
            return False
        # Only consider plausibly-secret strings — avoids flagging prose.
        if not looks_like_secret_charset(value):
            return False
        return shannon_entropy(value) >= self.threshold
