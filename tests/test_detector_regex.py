from __future__ import annotations

from redactly.detector import scan_string
from redactly.rules import DetectionType


def _types(hits):
    return {h.type for h in hits}


def test_detects_email():
    hits = scan_string("contact john@gmail.com for details")
    assert DetectionType.EMAIL in _types(hits)
    email_hit = next(h for h in hits if h.type == DetectionType.EMAIL)
    assert email_hit.value == "john@gmail.com"


def test_detects_aws_access_key():
    hits = scan_string("key=AKIAIOSFODNN7EXAMPLE")
    assert DetectionType.AWS_KEY in _types(hits)


def test_detects_stripe_key():
    hits = scan_string("charge with sk_live_abcdef1234567890")
    assert DetectionType.SECRET in _types(hits)


def test_detects_bearer_token():
    hits = scan_string("Authorization: Bearer abcdef1234567890deadbeef")
    assert DetectionType.TOKEN in _types(hits)


def test_detects_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123xyz"
    hits = scan_string(f"token {jwt}")
    assert DetectionType.TOKEN in _types(hits)


def test_no_false_positive_on_plain_text():
    hits = scan_string("the quick brown fox jumps over the lazy dog")
    assert hits == []


def test_phone_detected():
    hits = scan_string("call +1 415 555 0100 now")
    assert DetectionType.PHONE in _types(hits)
