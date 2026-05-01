from __future__ import annotations

import redactly
from redactly.masker import mask_value
from redactly.rules import DetectionType, Hit, MaskStyle


def _hit(value: str, t: DetectionType) -> Hit:
    return Hit(type=t, value=value, start=0, end=len(value))


def test_email_format_preserving():
    assert mask_value(_hit("john@gmail.com", DetectionType.EMAIL)) == "j***@gmail.com"


def test_phone_format_preserving():
    assert mask_value(_hit("9876543210", DetectionType.PHONE)) == "98******10"


def test_stripe_token_format_preserving():
    # Keep both the type and environment prefix so devs can correlate while still
    # masking the secret body.
    assert mask_value(_hit("sk_live_abc123xyz", DetectionType.SECRET)) == "sk_live_****xyz"


def test_full_redaction_mode():
    redactly.configure(mask_style=MaskStyle.FULL_REDACTION)
    assert mask_value(_hit("anything", DetectionType.SECRET)) == "[REDACTED_SECRET]"


def test_jwt_does_not_leak_header_or_payload():
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n7AvNUvIHa3prr-w"
    )
    masked = mask_value(_hit(jwt, DetectionType.TOKEN))
    # Header (alg) and payload (sub claim) must not be reconstructable.
    assert "eyJhbGc" not in masked
    assert "eyJzdWI" not in masked
    assert "1234567890" not in masked
    # Output is short and clearly redacted.
    assert "****" in masked
    assert len(masked) <= 12


def test_long_token_with_late_underscore_is_capped():
    # Underscore appears way past char 8 — should NOT become the prefix.
    v = "ABCDEFGHIJKLMNOP_qrstuvwxyz"
    masked = mask_value(_hit(v, DetectionType.SECRET))
    assert "ABCDEFGHIJKLMNOP" not in masked
    assert masked.startswith("AB")


def test_short_underscore_prefix_still_kept():
    # `sk_live_…`, `ghp_…` style — prefix is recognizable, keep it.
    assert mask_value(_hit("sk_live_abc123xyz", DetectionType.SECRET)) == "sk_live_****xyz"
    assert mask_value(_hit("ghp_abcdefghijklmnop", DetectionType.SECRET)) == "ghp_****nop"


def test_email_deterministic():
    a = mask_value(_hit("a@b.com", DetectionType.EMAIL))
    b = mask_value(_hit("a@b.com", DetectionType.EMAIL))
    assert a == b
