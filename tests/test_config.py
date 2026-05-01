from __future__ import annotations

import pytest

import redactly
from redactly.rules import Action, DetectionType, MaskStyle, Rule


def test_configure_returns_config_instance():
    cfg = redactly.configure(block_secrets=True)
    assert cfg.block_secrets is True


def test_configure_persists_across_calls():
    redactly.configure(block_secrets=True)
    redactly.configure(mask_emails=False)
    cfg = redactly.get_config()
    assert cfg.block_secrets is True
    assert cfg.mask_emails is False


def test_configure_rejects_unknown_keys():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        redactly.configure(nonexistent_flag=True)


def test_custom_rules_are_applied(captured_logs):
    redactly.configure(
        custom_rules=[
            Rule(pattern=r"internal_id_\d+", type=DetectionType.CUSTOM, action=Action.MASK)
        ]
    )
    logger = redactly.get_logger("redactly.test.custom")
    logger.info("object %s", "internal_id_42")
    rendered = captured_logs[0].getMessage()
    assert "internal_id_42" not in rendered


def test_mask_style_full_redaction(captured_logs):
    redactly.configure(mask_style=MaskStyle.FULL_REDACTION)
    logger = redactly.get_logger("redactly.test.full")
    logger.info("user %s", "john@gmail.com")
    rendered = captured_logs[0].getMessage()
    assert "[REDACTED_EMAIL]" in rendered
    assert "john@gmail.com" not in rendered


def test_reset_config_restores_defaults():
    redactly.configure(block_secrets=True, mask_emails=False)
    redactly.reset_config()
    cfg = redactly.get_config()
    assert cfg.block_secrets is False
    assert cfg.mask_emails is True
