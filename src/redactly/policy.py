from __future__ import annotations

from .config import get_config
from .rules import Action, DetectionType, Hit

_SECRET_TYPES = frozenset(
    {
        DetectionType.SECRET,
        DetectionType.TOKEN,
        DetectionType.AWS_KEY,
        DetectionType.ENTROPY,
    }
)


def decide(hit: Hit) -> Action:
    """Return the action to take for a given hit, per current config."""
    cfg = get_config()

    if hit.type in _SECRET_TYPES and cfg.block_secrets:
        return Action.BLOCK

    for rule in cfg.custom_rules:
        if rule.type == hit.type:
            return rule.action

    return cfg.default_policy
