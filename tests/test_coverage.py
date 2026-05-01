"""Targeted tests covering edge cases and extension hooks."""

from __future__ import annotations

import redactly
from redactly.detector import scan_mapping, scan_string
from redactly.masker import apply_to_string, mask_value
from redactly.policy import decide
from redactly.rules import Action, DetectionType, Hit, Rule
from redactly.utils import shannon_entropy

# ---- utils ----------------------------------------------------------------


def test_shannon_entropy_empty_returns_zero():
    assert shannon_entropy("") == 0.0


# ---- detector toggles -----------------------------------------------------


def test_mask_emails_false_suppresses_email_detection():
    redactly.configure(mask_emails=False)
    hits = scan_string("contact john@gmail.com")
    assert all(h.type != DetectionType.EMAIL for h in hits)


def test_mask_phones_false_suppresses_phone_detection():
    redactly.configure(mask_phones=False)
    hits = scan_string("ring +1 415 555 0100")
    assert all(h.type != DetectionType.PHONE for h in hits)


def test_entropy_rejects_non_charset_long_token():
    redactly.configure(entropy=True, entropy_threshold=3.0, entropy_min_length=20)
    # 26 chars, but contains '!' which isn't in the secret charset.
    hits = scan_string("helloworldhelloworldhelloworld!!!")
    assert all(h.type != DetectionType.ENTROPY for h in hits)


# ---- add_detector / add_masker --------------------------------------------


def test_add_detector_runs_after_builtins(captured_logs):
    def license_plate_detector(value: str) -> list[Hit]:
        import regex as re

        out = []
        for m in re.finditer(r"[A-Z]{3}-\d{4}", value):
            out.append(
                Hit(
                    type=DetectionType.CUSTOM,
                    value=m.group(0),
                    start=m.start(),
                    end=m.end(),
                    detector="license_plate",
                )
            )
        return out

    redactly.add_detector(license_plate_detector)
    logger = redactly.get_logger("redactly.test.cov.add_det")
    logger.info("plate is ABC-1234")
    rendered = captured_logs[0].getMessage()
    assert "ABC-1234" not in rendered


def test_add_masker_overrides_builtin(captured_logs):
    def to_scrubbed(hit: Hit) -> str | None:
        if hit.type == DetectionType.EMAIL:
            return "[SCRUBBED_EMAIL]"
        return None

    redactly.add_masker(to_scrubbed)
    logger = redactly.get_logger("redactly.test.cov.add_mask")
    logger.info("email is %s", "a@b.com")
    rendered = captured_logs[0].getMessage()
    assert "[SCRUBBED_EMAIL]" in rendered


# ---- logger edge cases ----------------------------------------------------


def test_filter_swallows_getmessage_errors():
    import logging

    from redactly.logger import RedactlyFilter

    f = RedactlyFilter()
    # %d applied to a string fails inside getMessage(); filter must still return True.
    rec = logging.LogRecord("n", logging.INFO, "p", 1, "value=%d", ("not-a-number",), None)
    assert f.filter(rec) is True


def test_tuple_args_with_mixed_types(captured_logs):
    logger = redactly.get_logger("redactly.test.cov.mixed")
    payload = {"password": "shh"}
    # Two args: one plain string, one dict — exercises the tuple loop's dict branch.
    logger.info("prefix=%s payload=%s", "plain", payload)
    assert payload == {"password": "shh"}  # untouched
    rendered = captured_logs[0].getMessage()
    assert "shh" not in rendered


def test_allow_policy_skips_masking(captured_logs, capsys):
    redactly.configure(default_policy=Action.ALLOW)
    logger = redactly.get_logger("redactly.test.cov.allow")
    logger.info("email is %s", "a@b.com")
    # Value preserved; no warning either.
    assert "a@b.com" in captured_logs[0].getMessage()
    assert capsys.readouterr().err == ""


# ---- masker span replacement inside structured payload --------------------


def test_embedded_email_in_extras_span_replaced(captured_logs):
    logger = redactly.get_logger("redactly.test.cov.span")
    logger.info("event", extra={"note": "ping j@b.com now"})
    note = captured_logs[0].note
    assert "j@b.com" not in note
    assert "ping" in note and "now" in note  # surrounding text preserved


def test_int_dict_keys_masked_via_fallback(captured_logs):
    logger = redactly.get_logger("redactly.test.cov.intkey")
    logger.info("event", extra={"by_id": {1: "john@gmail.com"}})
    assert captured_logs[0].by_id[1] == "j***@gmail.com"


# ---- masker helpers -------------------------------------------------------


def test_mask_email_with_no_at_sign_falls_back():
    # Artificial Hit: value labeled EMAIL but contains no "@".
    h = Hit(type=DetectionType.EMAIL, value="noatsign", start=0, end=8)
    assert mask_value(h) == "*" * 8


def test_mask_phone_with_few_digits_falls_back():
    h = Hit(type=DetectionType.PHONE, value="12-3", start=0, end=4)
    assert mask_value(h) == "****"


def test_mask_generic_short_value():
    h = Hit(type=DetectionType.PII, value="ab", start=0, end=2)
    assert mask_value(h) == "**"


def test_apply_to_string_with_no_hits_returns_value():
    assert apply_to_string("plain text", []) == "plain text"


# ---- policy ---------------------------------------------------------------


def test_custom_type_hit_without_rule_uses_default_policy():
    # CUSTOM type, no matching custom_rules → falls through to default_policy.
    h = Hit(type=DetectionType.CUSTOM, value="x", start=0, end=1)
    assert decide(h) == Action.MASK


def test_custom_rule_applied_before_default():
    redactly.configure(
        custom_rules=[Rule(pattern=r"doesnt-matter", type=DetectionType.PII, action=Action.ALLOW)]
    )
    h = Hit(type=DetectionType.PII, value="x", start=0, end=1)
    assert decide(h) == Action.ALLOW


# ---- scan_mapping list tracking ------------------------------------------


def test_scan_mapping_list_of_strings():
    hits = scan_mapping(["contact a@b.com", "plain"])
    assert any(h.type == DetectionType.EMAIL for h in hits)


def test_scan_mapping_tuple_of_dicts():
    hits = scan_mapping(({"password": "p1"}, {"password": "p2"}))
    secrets = [h for h in hits if h.type == DetectionType.SECRET]
    assert len(secrets) == 2
