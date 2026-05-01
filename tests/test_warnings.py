from __future__ import annotations

import redactly


def test_warning_contains_expected_fields(captured_logs, capsys):
    logger = redactly.get_logger("redactly.test.warn")
    logger.info({"password": "hunter2"})
    err = capsys.readouterr().err
    assert "[REDACTLY WARNING]" in err
    assert "Type: SECRET" in err
    assert "Key: password" in err
    assert "Action: MASKED" in err
    assert "test_warnings.py:" in err


def test_telemetry_hook_invoked(captured_logs):
    events = []
    redactly.configure(telemetry_hook=events.append)
    logger = redactly.get_logger("redactly.test.telemetry")
    logger.info({"email": "a@b.com"})
    assert len(events) == 1
    evt = events[0]
    assert evt["type"] == "EMAIL"
    assert evt["action"] == "masked"
    assert evt["key"] == "email"
    assert "test_warnings.py" in evt["source"]


def test_dev_warnings_can_be_disabled(captured_logs, capsys):
    redactly.configure(dev_warnings=False)
    logger = redactly.get_logger("redactly.test.warn_off")
    logger.info("login", extra={"password": "hunter2"})
    err = capsys.readouterr().err
    assert err == ""
    # Masking still happens.
    assert captured_logs[0].password != "hunter2"


def test_telemetry_hook_still_fires_when_dev_warnings_off(captured_logs):
    events = []
    redactly.configure(dev_warnings=False, telemetry_hook=events.append)
    logger = redactly.get_logger("redactly.test.warn_off_telem")
    logger.info({"email": "a@b.com"})
    assert len(events) == 1


def test_telemetry_hook_errors_are_swallowed(captured_logs):
    def bad_hook(_):
        raise RuntimeError("boom")

    redactly.configure(telemetry_hook=bad_hook)
    logger = redactly.get_logger("redactly.test.bad_hook")
    # Should not raise despite the hook exploding.
    logger.info({"email": "a@b.com"})
