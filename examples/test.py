"""Manual playground for redactly.

Run from the project root:

    .venv/bin/python manual_test/test.py

To experiment:
  * Edit the values in the EDIT_ME block below.
  * Tweak `manual_test/redactly_config.py` to flip masking/blocking modes.
  * Set REDACTLY_DISABLED=1 in your shell to fully bypass and see raw output.
"""

from __future__ import annotations

import copy
import logging
import sys
from pathlib import Path

# Make `import redactly` and `import redactly_config` work whether you run
# this file via `python manual_test/test.py` or `.venv/bin/python ...`.
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent / "src"))
sys.path.insert(0, str(_HERE))

from redactly_config import apply as apply_config  # noqa: E402

import redactly  # noqa: E402

# ──────────────────────────── EDIT ME ─────────────────────────────────────
# Change anything here — re-run the script to see how redactly handles it.

EMAIL = "john.doe@gmail.com"
PHONE = "+1 415 555 0100"
PASSWORD = "supersecret123"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n7AvNUvIHa3prr-w"
RANDOM_PROSE = "Just a friendly hello to the operations team."
CUSTOM_ID = "internal_id_42"
NESTED_PAYLOAD = {
    "user": {
        "email": EMAIL,
        "phone": PHONE,
        "credentials": {"password": PASSWORD, "api_key": AWS_KEY},
    },
    "request_id": CUSTOM_ID,
    "tags": ["normal-tag", f"contact={EMAIL}"],
}

# ──────────────────────────────────────────────────────────────────────────


def banner(title: str) -> None:
    print(f"\n{'─' * 8} {title} {'─' * (60 - len(title))}")


def setup_logging() -> logging.Logger:
    # Plain stdout handler — masks happen BEFORE this prints.
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[stdout] %(levelname)-7s %(name)s :: %(message)s"))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    return redactly.get_logger("manual_test")


def main() -> None:
    apply_config()
    logger = setup_logging()

    banner("1. f-string interpolation")
    logger.info(f"new signup: email={EMAIL} phone={PHONE}")

    banner("2. %-style args")
    logger.warning("login failed for %s with token %s", EMAIL, JWT)

    banner("3. structured 'extra' kwarg (most common in production)")
    logger.info("user_event", extra=NESTED_PAYLOAD)

    banner("4. dict as the message itself")
    logger.info({"email": EMAIL, "password": PASSWORD, "note": "logging this raw"})

    banner("5. mixing PII and secrets in one call")
    logger.info(
        "outgoing request",
        extra={
            "headers": {"Authorization": f"Bearer {JWT}"},
            "body": {"email": EMAIL, "credit_card_holder": "John Doe"},
        },
    )

    banner("6. clean log (nothing to detect)")
    logger.info(RANDOM_PROSE)

    banner("7. custom rule from config")
    logger.info(f"processing record {CUSTOM_ID}")

    banner("8. block mode (raises RedactlyBlockedError)")
    redactly.configure(block_secrets=True)
    try:
        logger.error("token leak: %s", AWS_KEY)
    except redactly.RedactlyBlockedError as e:
        print(f"  ✗ caught RedactlyBlockedError: {e}")
    redactly.configure(block_secrets=False)  # reset for any further runs

    banner("9. caller's data is never mutated")
    creds = NESTED_PAYLOAD["user"]["credentials"]
    before = copy.deepcopy(creds)
    # Pass as %s so the formatter renders the masked dict into the log line
    # (otherwise the masked copy lives only on record.creds).
    logger.info("event creds=%s", creds)
    print(f"  caller's dict unchanged:    {creds == before}")
    print(f"  caller still has originals: {creds}")

    banner("done")
    print(
        "Tip: edit manual_test/redactly_config.py to switch mask styles, enable "
        "entropy detection, or change the default policy."
    )


if __name__ == "__main__":
    main()
