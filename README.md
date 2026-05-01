# redactly

[![CI](https://github.com/gupsho/redactly/actions/workflows/ci.yml/badge.svg)](https://github.com/gupsho/redactly/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/redactly.svg)](https://pypi.org/project/redactly/)
[![Python](https://img.shields.io/pypi/pyversions/redactly.svg)](https://pypi.org/project/redactly/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**A drop-in Python logging SDK that stops you from leaking secrets and PII — without adding a new logging API.**

Most "logging" incidents aren't hacks. Someone logged a request body. Someone added `logger.info(user.__dict__)` during debugging and shipped it. Someone did `f"token={t}"`. Your SIEM, your S3 log archive, your APM vendor, your grep-in-terminal — they all now have the data.

`redactly` wraps Python's standard `logging` module and scrubs sensitive values at the boundary, so the leak never makes it to disk or to a vendor.

```python
from redactly import get_logger

logger = get_logger(__name__)
logger.info(f"new user {email}")
# stdout: new user j***@gmail.com
# stderr: [REDACTLY WARNING] Type: EMAIL Key: <message> Location: app.py:42 Action: MASKED
```

- ✅ **Zero config**: `get_logger(__name__)` — that's it.
- ✅ **Drop-in**: returns a stdlib `logging.Logger`. Works with any handler, formatter, or log shipper you already use.
- ✅ **Safe by default**: deep-copies structured payloads before masking, so your application state is never mutated.
- ✅ **Dev-loud**: every masked or blocked value prints a stderr warning pointing at the caller's `file:line`.
- ✅ **100% test coverage**, strict mypy, pure Python.

---

## Table of contents

- [Install](#install)
- [Quick start](#quick-start)
- [What gets detected](#what-gets-detected)
- [Masking styles](#masking-styles)
- [Block mode (strict)](#block-mode-strict)
- [Structured logging](#structured-logging)
- [Configuration](#configuration)
- [Custom rules, detectors, and maskers](#custom-rules-detectors-and-maskers)
- [Telemetry hook](#telemetry-hook)
- [Performance](#performance)
- [How it works](#how-it-works)
- [Disabling in production](#disabling-in-production)
- [FAQ](#faq)
- [Development](#development)
- [License](#license)

---

## Install

```sh
pip install redactly
```

Requires Python **3.13+**. Runtime dependencies: `pydantic>=2`, `regex>=2024.0`.

---

## Quick start

```python
from redactly import get_logger

logger = get_logger(__name__)
logger.info(f"user email is {email}")
```

Output:

```
user email is j***@gmail.com
```

And on stderr:

```
[REDACTLY WARNING]
Type: EMAIL
Key: <message>
Location: signup.py:42
Action: MASKED
```

No setup. Detection, masking, and warnings are all on by default.

---

## What gets detected

| Detector          | Examples                                                         |
|-------------------|------------------------------------------------------------------|
| Email             | `john@gmail.com`                                                 |
| Phone             | `+1 415 555 0100`, `9876543210`                                  |
| AWS access keys   | `AKIAIOSFODNN7EXAMPLE`, `ASIA…`                                  |
| Stripe-style keys | `sk_live_…`, `pk_test_…`, `rk_live_…`                            |
| GitHub tokens     | `ghp_…`, `gho_…`, `ghu_…`, `ghs_…`, `ghr_…`                      |
| JWTs              | `eyJ…h1…w3…`                                                     |
| Bearer tokens     | `Authorization: Bearer …`, `token=…`, `api_key=…`                |
| Sensitive keys    | dict keys containing `password`, `secret`, `token`, `auth`, `api_key`, `credential`, `session`, `cookie`, `private_key` |
| High entropy      | opt-in (`configure(entropy=True)`) — strings that look random    |
| Custom            | whatever regex/rule/callable you register                         |

All regexes are precompiled at config time; scanning is linear in input length.

---

## Masking styles

Two modes, switchable via `configure(mask_style=...)`:

### `FORMAT_PRESERVING` (default)

Keeps the shape so a developer can correlate log lines without seeing the value.

| Input                   | Output              |
|-------------------------|---------------------|
| `john@gmail.com`        | `j***@gmail.com`    |
| `9876543210`            | `98******10`        |
| `sk_live_abc123xyz`     | `sk_****xyz`        |
| `AKIAIOSFODNN7EXAMPLE`  | `AK****PLE`         |

### `FULL_REDACTION`

No shape, no correlation. Maximum caution.

| Input                | Output              |
|----------------------|---------------------|
| `john@gmail.com`     | `[REDACTED_EMAIL]`  |
| `sk_live_abc123xyz`  | `[REDACTED_SECRET]` |

```python
from redactly import configure, MaskStyle
configure(mask_style=MaskStyle.FULL_REDACTION)
```

---

## Block mode (strict)

If a secret being logged is a bug (not a routine mask), you probably want to fail loudly. Enable block mode and redactly will raise `RedactlyBlockedError` at the call site — the log record is discarded and never reaches any handler.

```python
from redactly import configure, get_logger, RedactlyBlockedError

configure(block_secrets=True)
logger = get_logger(__name__)

try:
    logger.info({"email": "john@gmail.com", "password": "supersecret123"})
except RedactlyBlockedError as e:
    # e.location == "user_service.py:42"
    # e.hit_type == "SECRET"
    # e.key == "password"
    ...
```

Stderr:

```
[REDACTLY WARNING]
Type: EMAIL
Key: email
Location: user_service.py:42
Action: MASKED
[REDACTLY WARNING]
Type: SECRET
Key: password
Location: user_service.py:42
Action: BLOCKED
```

`block_secrets=True` only blocks secret/token-family hits. PII (emails, phones) still mask unless you set the default policy explicitly.

---

## Structured logging

redactly scans `extra=`, dict-valued messages, and dict args recursively, and **never mutates the caller's data** — it deep-copies before masking.

```python
user = {"email": "x@y.com", "profile": {"password": "p1"}}
logger.info("login", extra={"user": user})

# user == {"email": "x@y.com", "profile": {"password": "p1"}}   ← untouched
# record.user == {"email": "x***@y.com", "profile": {"password": "p*"}}
```

Works with:

- `logger.info({"key": value})` — dict as message
- `logger.info("fmt %s", dict_payload)` — dict as positional arg
- `logger.info("event", extra={"body": {...}})` — nested extras
- lists of dicts, tuples of dicts, arbitrary nesting

---

## Configuration

Call once at startup (or never — the defaults work).

```python
from redactly import configure, Action, MaskStyle, Rule, DetectionType

configure(
    enabled=True,                              # global kill switch
    default_policy=Action.MASK,                # MASK | BLOCK | ALLOW
    block_secrets=True,                        # force BLOCK for all secret-family hits
    mask_emails=True,
    mask_phones=True,
    entropy=False,                             # enable Shannon-entropy secret detection
    entropy_threshold=4.5,                     # bits/char (typical high-entropy: 4.0–5.0)
    entropy_min_length=20,                     # skip anything shorter
    mask_style=MaskStyle.FORMAT_PRESERVING,    # or FULL_REDACTION
    custom_rules=[                             # your own regex → action
        Rule(pattern=r"internal_id_\d+",
             type=DetectionType.CUSTOM,
             action=Action.MASK),
    ],
    telemetry_hook=lambda event: ...,          # see below
)
```

`configure()` can be called multiple times; later calls override earlier ones. Unknown kwargs raise `pydantic.ValidationError`. A global `threading.Lock` guards writes; reads are lock-free.

---

## Custom rules, detectors, and maskers

Three increasing levels of customization:

### 1. `custom_rules` — regex with an action

```python
from redactly import configure, Rule, DetectionType, Action

configure(custom_rules=[
    Rule(pattern=r"CC-\d{16}", type=DetectionType.CUSTOM, action=Action.BLOCK),
    Rule(pattern=r"employee-\d+", type=DetectionType.PII, action=Action.MASK),
])
```

### 2. `add_detector` — arbitrary Python detector

```python
from redactly import add_detector, Hit, DetectionType

def detect_license_plate(value: str) -> list[Hit]:
    import regex as re
    return [
        Hit(type=DetectionType.CUSTOM,
            value=m.group(0), start=m.start(), end=m.end(),
            detector="license_plate")
        for m in re.finditer(r"[A-Z]{3}-\d{4}", value)
    ]

add_detector(detect_license_plate)
```

Runs after the built-in detectors on every string scan.

### 3. `add_masker` — custom replacement

```python
from redactly import add_masker, Hit, DetectionType

def mask_phone_by_country(hit: Hit) -> str | None:
    if hit.type == DetectionType.PHONE and hit.value.startswith("+91"):
        return "+91 **********"
    return None          # fall through to built-in masking

add_masker(mask_phone_by_country)
```

Return `None` to defer to the built-in masker.

---

## Telemetry hook

Emit one event per masked/blocked hit to any sink you like — metrics, SIEM, Slack.

```python
import statsd

def redactly_event(event: dict) -> None:
    statsd.incr(f"redactly.{event['type'].lower()}.{event['action']}")

configure(telemetry_hook=redactly_event)
```

Event shape:

```python
{
    "type":      "EMAIL",            # DetectionType
    "action":    "masked",           # "masked" | "blocked" | "allowed"
    "key":       "email",            # the dict key, or None for message-level
    "source":    "signup.py:42",     # caller file:line
    "detector":  "email",            # which detector fired
    "timestamp": 1714088400.0,       # epoch seconds
}
```

Exceptions raised inside the hook are swallowed — the hook can never break logging.

---

## Performance

The filter is on the per-log hot path, so redactly is optimized for the common case of **zero hits**:

- **No deep copy unless necessary** — structured payloads are scanned in place; a deep copy is only made for sources that have maskable hits.
- **Precompiled patterns** — the global pattern tuple is rebuilt only when `configure()` is called.
- **Cached entropy detector** — lifted out of the per-scan loop.
- **Zero-cost short-circuit** — `REDACTLY_DISABLED=1` or `configure(enabled=False)` returns from the filter in a single config lookup.

Target overhead: **< 1 ms per log call** for a ~1 KB payload. You can benchmark with your own workload; see `tests/` for representative shapes.

---

## How it works

```
logger.info(...)
      │
      ▼
┌──────────────────────────┐
│ stdlib logging.Logger    │
└──────────────────────────┘
      │  LogRecord
      ▼
┌──────────────────────────┐
│ RedactlyFilter.filter()  │   ← attached idempotently by get_logger()
│  1. scan (read-only)     │
│       • message          │
│       • args             │
│       • extras           │
│  2. decide per hit       │   → mask / block / allow
│  3. warn on stderr       │   → one warning per unique (type, value)
│  4. if any block: raise  │
│  5. deep-copy + mask     │   ← only the sources that need it
└──────────────────────────┘
      │  LogRecord (masked)
      ▼
┌──────────────────────────┐
│ your handlers/formatters │
└──────────────────────────┘
```

Module map (`src/redactly/`):

| Module                 | Role                                                         |
|------------------------|--------------------------------------------------------------|
| `logger.py`            | `get_logger()` + `RedactlyFilter` (the hot path)             |
| `detector.py`          | scan orchestrator, custom pattern cache                       |
| `detectors/regex.py`   | built-in regex patterns (email, AWS, Stripe, JWT, …)         |
| `detectors/key_based.py` | sensitive-key substring match                              |
| `detectors/entropy.py` | Shannon-entropy secret detector (opt-in)                     |
| `masker.py`            | format-preserving + full-redaction; string + structure walker |
| `policy.py`            | hit → action decision table                                  |
| `warnings.py`          | stderr warning + telemetry dispatch                          |
| `config.py`            | pydantic `Config`, `configure()`, global singleton           |
| `rules.py`             | `Rule`, `Hit`, `DetectionType`, `Action`, `MaskStyle`        |
| `exceptions.py`        | `RedactlyBlockedError`                                       |

---

## Disabling in production

Two ways, env var wins:

```sh
export REDACTLY_DISABLED=1       # also accepts "true", "yes", "on" (case-insensitive)
```

```python
from redactly import configure
configure(enabled=False)
```

When disabled the filter returns on the first line — no scanning, no allocations, no env re-lookup beyond a single `os.environ.get`.

---

## FAQ

**Does it slow down logs that don't contain secrets?**
Minimal. The scan walks string inputs once with precompiled regex. The expensive step (deep copy) is skipped entirely when no maskable hits are found.

**What happens with `logger.info("%d", "not-a-number")`?**
`record.getMessage()` raises inside the filter; redactly catches it and lets the record through unchanged. The stdlib handler will handle the format error the same way it always does.

**Does it mutate my dict if I log it?**
No. Structured payloads are deep-copied before masking. The caller's object is never modified.

**How do I log something I know is safe, like a user's public handle?**
Either set the default policy to `ALLOW`, or wrap the value — `redactly` only scans strings; `Path("safe")` or `SafeStr("safe")` won't trigger detection.

**Why `print` to stderr instead of using a logger for warnings?**
Because redactly *is* the logger. Using `logging` for our own warnings would recurse.

**Can I run it alongside structlog / loguru / logbook?**
If the upstream library emits through stdlib `logging` (structlog does by default, loguru has an `InterceptHandler` pattern), yes. redactly attaches to the stdlib logger hierarchy.

**Is there a dashboard?**
No — explicit non-goal for v1. Pipe `telemetry_hook` events to wherever you already dashboard.

---

## Development

### Setup

```sh
git clone https://github.com/gupsho/redactly.git
cd redactly
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install          # one-time, sets up the git pre-commit hook
```

### Test, lint, type-check

```sh
pytest                      # 74 tests, 100% coverage
ruff check .
ruff format --check .
mypy src/redactly
```

Or in one shot:

```sh
pre-commit run --all-files
```

The `pre-commit` hook runs `ruff check --fix`, `ruff format`, and `mypy` on every commit. If anything fails, the commit is aborted and you can inspect the changes before retrying.

### Project layout

```
redactly/
├── src/redactly/          # package
├── tests/                 # pytest suite (conftest auto-resets global state)
├── pyproject.toml         # build + tooling config
└── .pre-commit-config.yaml
```

### Conventions

- No runtime dependencies beyond `pydantic` and `regex`.
- Every public name is re-exported from `redactly/__init__.py`.
- Global state (config, custom patterns, extra detectors/maskers) is reset per test via `tests/conftest.py`.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full release history. Highlights are
also published as GitHub Releases on every tagged version.

---

## License

MIT — see [LICENSE](LICENSE).
