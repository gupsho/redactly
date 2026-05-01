"""Sample redactly configuration.

Edit this file to try different settings, then re-run `python examples/test.py`.
"""

from __future__ import annotations

import redactly
from redactly import Action, DetectionType, MaskStyle, Rule


def apply() -> None:
    """Configure redactly. Toggle the options below to experiment."""

    redactly.configure(
        # ─── Master switch ────────────────────────────────────────────────
        enabled=True,  # set False (or env REDACTLY_DISABLED=1) to fully bypass
        # ─── Default policy for any detected hit ──────────────────────────
        default_policy=Action.MASK,  # MASK | BLOCK | ALLOW
        # ─── Block mode (raises RedactlyBlockedError on secret hits) ──────
        block_secrets=False,  # try True to see the exception path
        # ─── Dev feedback (the [REDACTLY WARNING] stderr blocks) ──────────
        dev_warnings=False,  # set False to silence the stderr warnings
        # ─── PII gating ───────────────────────────────────────────────────
        mask_emails=True,
        mask_phones=True,
        # ─── Entropy-based secret detection (opt-in, can have false +ves) ──
        entropy=False,  # try True to flag long random-looking strings
        entropy_threshold=4.5,  # bits/char; 4.0–5.0 is high entropy
        entropy_min_length=20,
        # ─── Masking style ────────────────────────────────────────────────
        mask_style=MaskStyle.FORMAT_PRESERVING,  # or MaskStyle.FULL_REDACTION
        # ─── Custom regex rules ───────────────────────────────────────────
        custom_rules=[
            Rule(
                pattern=r"internal_id_\d+",
                type=DetectionType.CUSTOM,
                action=Action.MASK,
            ),
            # Add more — e.g. credit-card-ish:
            # Rule(pattern=r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b",
            #      type=DetectionType.SECRET, action=Action.BLOCK),
        ],
        # ─── Telemetry hook (gets one event per masked/blocked hit) ───────
        # telemetry_hook=_print_telemetry,
        telemetry_hook=None,
    )


def _print_telemetry(event: dict[str, object]) -> None:
    """Default sample hook — prints each detection event to stdout."""
    print(f"  [telemetry] {event}")
