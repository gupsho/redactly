from __future__ import annotations

from redactly.detector import scan_mapping
from redactly.rules import DetectionType


def test_detects_password_key():
    hits = scan_mapping({"password": "hunter2"})
    assert any(h.type == DetectionType.SECRET and h.value == "hunter2" for h in hits)


def test_detects_nested_token():
    hits = scan_mapping({"user": {"auth_token": "deadbeef"}})
    secret_hits = [h for h in hits if h.type == DetectionType.SECRET]
    assert any(h.value == "deadbeef" for h in secret_hits)


def test_case_insensitive_key_match():
    hits = scan_mapping({"API_KEY": "abc123"})
    assert any(h.type == DetectionType.SECRET for h in hits)


def test_list_of_dicts():
    hits = scan_mapping([{"secret": "a"}, {"secret": "b"}])
    assert sum(1 for h in hits if h.type == DetectionType.SECRET) == 2


def test_non_sensitive_key_still_scans_regex():
    hits = scan_mapping({"note": "contact me at jane@acme.com"})
    assert any(h.type == DetectionType.EMAIL for h in hits)


def test_ignores_non_string_values():
    hits = scan_mapping({"password": 42})
    # Integers skipped; only strings scanned.
    assert hits == []
