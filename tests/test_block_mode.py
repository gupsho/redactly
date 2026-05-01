from __future__ import annotations

import pytest

import redactly


def test_block_secrets_raises(captured_logs):
    redactly.configure(block_secrets=True)
    logger = redactly.get_logger("redactly.test.block")
    with pytest.raises(redactly.RedactlyBlockedError):
        logger.info({"password": "supersecret123"})
    # Record was never emitted.
    assert captured_logs == []


def test_block_message_mentions_location(capsys):
    redactly.configure(block_secrets=True)
    logger = redactly.get_logger("redactly.test.block_loc")
    with pytest.raises(redactly.RedactlyBlockedError) as exc_info:
        logger.info("AKIAIOSFODNN7EXAMPLE")
    assert "test_block_mode.py" in exc_info.value.location


def test_block_emits_warning_before_raising(capsys):
    redactly.configure(block_secrets=True)
    logger = redactly.get_logger("redactly.test.block_warn")
    with pytest.raises(redactly.RedactlyBlockedError):
        logger.info("token %s", "AKIAIOSFODNN7EXAMPLE")
    err = capsys.readouterr().err
    assert "[REDACTLY WARNING]" in err
    assert "Action: BLOCKED" in err


def test_email_pii_does_not_block_under_block_secrets():
    redactly.configure(block_secrets=True)
    logger = redactly.get_logger("redactly.test.block_email")
    # block_secrets only affects secret-type hits; email gets masked, not blocked.
    logger.info({"email": "j@b.com"})
