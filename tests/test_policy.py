from __future__ import annotations

import redactly
from redactly.policy import decide
from redactly.rules import Action, DetectionType, Hit


def _hit(t: DetectionType) -> Hit:
    return Hit(type=t, value="x", start=0, end=1)


def test_default_policy_is_mask():
    assert decide(_hit(DetectionType.EMAIL)) == Action.MASK
    assert decide(_hit(DetectionType.SECRET)) == Action.MASK


def test_block_secrets_true_blocks_secrets_only():
    redactly.configure(block_secrets=True)
    assert decide(_hit(DetectionType.SECRET)) == Action.BLOCK
    assert decide(_hit(DetectionType.TOKEN)) == Action.BLOCK
    assert decide(_hit(DetectionType.EMAIL)) == Action.MASK


def test_allow_default_policy_passes_through():
    redactly.configure(default_policy=Action.ALLOW)
    assert decide(_hit(DetectionType.EMAIL)) == Action.ALLOW
