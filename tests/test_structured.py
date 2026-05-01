from __future__ import annotations

import redactly


def test_original_nested_dict_untouched(captured_logs):
    logger = redactly.get_logger("redactly.test.struct1")
    user = {"profile": {"email": "x@y.com", "tags": ["a", "b"]}}
    logger.info("event", extra={"user": user})
    # Nothing mutated on the caller side.
    assert user == {"profile": {"email": "x@y.com", "tags": ["a", "b"]}}


def test_list_of_secrets(captured_logs):
    logger = redactly.get_logger("redactly.test.struct2")
    logger.info("event", extra={"tokens": ["AKIAIOSFODNN7EXAMPLE", "AKIAJOSFODNN7EXAMPLE"]})
    tokens = captured_logs[0].tokens
    assert all("AKIA" not in t or "*" in t for t in tokens)


def test_deeply_nested_token(captured_logs):
    logger = redactly.get_logger("redactly.test.struct3")
    logger.info(
        "event",
        extra={"req": {"headers": {"authorization": "Bearer abcdef1234567890ABCDEF"}}},
    )
    auth = captured_logs[0].req["headers"]["authorization"]
    assert "abcdef1234567890ABCDEF" not in auth


def test_tuple_args_with_dict(captured_logs):
    logger = redactly.get_logger("redactly.test.struct4")
    payload = {"password": "mypassword"}
    logger.info("payload %s", payload)
    # Rendered message contains the str(dict) representation — it should be scanned
    # and the password value masked.
    rendered = captured_logs[0].getMessage()
    assert "mypassword" not in rendered


def test_format_arg_dict_with_only_key_based_secrets(captured_logs):
    """Regression: when args is a dict with sensitive keys (no regex match in
    the rendered text), the rendered message must still mask via key-based
    detection. Prior versions left the password plaintext in record.msg."""
    logger = redactly.get_logger("redactly.test.struct5")
    creds = {"password": "supersecret123", "note": "ignore me"}
    logger.info("event creds=%s", creds)
    rendered = captured_logs[0].getMessage()
    assert "supersecret123" not in rendered
    assert "ignore me" in rendered  # benign content preserved
    # Caller's dict untouched.
    assert creds == {"password": "supersecret123", "note": "ignore me"}


def test_format_arg_with_both_regex_and_key_based_hits(captured_logs):
    """Both regex (AWS key) and key-based (password) detections must land in
    the rendered output."""
    logger = redactly.get_logger("redactly.test.struct6")
    creds = {"password": "supersecret123", "api_key": "AKIAIOSFODNN7EXAMPLE"}
    logger.info("event creds=%s", creds)
    rendered = captured_logs[0].getMessage()
    assert "supersecret123" not in rendered
    assert "AKIAIOSFODNN7EXAMPLE" not in rendered
