from __future__ import annotations

import redactly


def test_f_string_message_masked(captured_logs):
    logger = redactly.get_logger("redactly.test.f_string")
    logger.info(f"user email is {'john@gmail.com'}")
    assert len(captured_logs) == 1
    rendered = captured_logs[0].getMessage()
    assert "john@gmail.com" not in rendered
    assert "j***@gmail.com" in rendered


def test_percent_style_args_masked(captured_logs):
    logger = redactly.get_logger("redactly.test.pct")
    logger.info("hello %s", "jane@acme.com")
    rendered = captured_logs[0].getMessage()
    assert "jane@acme.com" not in rendered


def test_extras_deep_copied_not_mutated(captured_logs):
    logger = redactly.get_logger("redactly.test.extras")
    payload = {"email": "x@y.com"}
    logger.info("user_event", extra={"user": payload})
    # Caller payload unchanged.
    assert payload == {"email": "x@y.com"}
    # Record has masked version.
    assert captured_logs[0].user == {"email": "x***@y.com"}


def test_nested_password_masked(captured_logs):
    logger = redactly.get_logger("redactly.test.nested")
    logger.info("login", extra={"body": {"password": "supersecret123"}})
    assert captured_logs[0].body["password"] != "supersecret123"
    assert captured_logs[0].body["password"].startswith("s")


def test_dict_message_masked(captured_logs):
    logger = redactly.get_logger("redactly.test.dict_msg")
    original = {"email": "john@gmail.com", "note": "hi"}
    logger.info(original)
    assert original["email"] == "john@gmail.com"  # unmodified
    msg = captured_logs[0].msg
    assert isinstance(msg, dict)
    assert msg["email"] == "j***@gmail.com"


def test_no_sensitive_data_passes_through(captured_logs):
    logger = redactly.get_logger("redactly.test.clean")
    logger.info("nothing to see here")
    assert captured_logs[0].getMessage() == "nothing to see here"


def test_get_logger_idempotent():
    a = redactly.get_logger("redactly.test.repeat")
    b = redactly.get_logger("redactly.test.repeat")
    assert a is b
    # Only one filter instance added (tracked via attr, not count).
    filter_count = sum(1 for f in a.filters if f.__class__.__name__ == "RedactlyFilter")
    assert filter_count == 1


def test_disabled_via_configure(captured_logs):
    redactly.configure(enabled=False)
    logger = redactly.get_logger("redactly.test.disabled")
    logger.info("email: john@gmail.com")
    assert "john@gmail.com" in captured_logs[0].getMessage()


def test_location_includes_file_and_line(captured_logs, capsys):
    logger = redactly.get_logger("redactly.test.loc")
    logger.info("email %s", "a@b.com")
    err = capsys.readouterr().err
    assert "[REDACTLY WARNING]" in err
    assert "test_logger.py:" in err


def test_logs_caller_file_not_redactly_internals(captured_logs):
    logger = redactly.get_logger("redactly.test.path")
    logger.info("email %s", "a@b.com")
    # Logging's stack walker should have landed on this test file's frame.
    assert captured_logs[0].pathname.endswith("test_logger.py")


def test_supports_all_log_levels(captured_logs):
    logger = redactly.get_logger("redactly.test.levels")
    logger.debug("d %s", "a@b.com")
    logger.info("i %s", "a@b.com")
    logger.warning("w %s", "a@b.com")
    logger.error("e %s", "a@b.com")
    for rec in captured_logs:
        assert "a@b.com" not in rec.getMessage()
    assert [r.levelname for r in captured_logs] == ["DEBUG", "INFO", "WARNING", "ERROR"]


def test_dedup_single_warning_for_repeated_value(capsys, captured_logs):
    logger = redactly.get_logger("redactly.test.dedup")
    logger.info("%s and again %s", "a@b.com", "a@b.com")
    err = capsys.readouterr().err
    assert err.count("[REDACTLY WARNING]") == 1


def test_env_disable_overrides_configure(monkeypatch, captured_logs):
    monkeypatch.setenv("REDACTLY_DISABLED", "1")
    redactly.configure(enabled=True)
    logger = redactly.get_logger("redactly.test.envdisable")
    logger.info("email=%s", "a@b.com")
    assert "a@b.com" in captured_logs[0].getMessage()
