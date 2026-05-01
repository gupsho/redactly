from __future__ import annotations

import redactly
from redactly.detector import scan_string
from redactly.rules import DetectionType


def test_entropy_off_by_default():
    hits = scan_string("abc123ZYXdefGHIjkl09876XYZ")
    # Might still be caught by other detectors? It looks random but matches no regex.
    assert all(h.type != DetectionType.ENTROPY for h in hits)


def test_entropy_detects_high_entropy_when_enabled():
    redactly.configure(entropy=True, entropy_threshold=3.5, entropy_min_length=20)
    hits = scan_string("random=aZ9kPq2mBv7xRcN4sYtW8EuXhLo")
    assert any(h.type == DetectionType.ENTROPY for h in hits)


def test_entropy_skips_short_strings():
    redactly.configure(entropy=True, entropy_threshold=3.0, entropy_min_length=20)
    hits = scan_string("aZ9kPq")
    assert all(h.type != DetectionType.ENTROPY for h in hits)


def test_entropy_ignores_prose():
    redactly.configure(entropy=True)
    hits = scan_string("this is a normal english sentence without secrets")
    assert all(h.type != DetectionType.ENTROPY for h in hits)
