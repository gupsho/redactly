# Changelog

All notable changes to redactly will be documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] — 2026-05-01

### Changed
- `[project.urls]` in `pyproject.toml` now points at the canonical GitHub
  repository (`gupsho/redactly`) and exposes `Repository`, `Issues`,
  `Changelog`, and `Documentation` entries so PyPI's sidebar is fully
  populated.
- README clone URL updated to match.

### Notes
- No code changes versus `0.1.0`. The bump exists only because PyPI metadata
  is frozen per release.

## [0.1.0] — 2026-05-01

### Added
- Initial public release.
- `get_logger(name)` — drop-in `logging.Logger` with redactly's filter
  attached. Idempotent across repeated calls.
- `RedactlyFilter` — intercepts every `LogRecord`, scans message / args /
  extras for sensitive content, masks or blocks per the active policy, and
  emits a `[REDACTLY WARNING]` block to stderr per unique `(type, value)`.
- Built-in detectors: emails, phones, AWS access keys (`AKIA…`, `ASIA…`),
  Stripe-style keys (`sk_live_…`, `pk_test_…`), GitHub tokens (`ghp_…`,
  `gho_…`, `ghu_…`, `ghs_…`, `ghr_…`), JWTs, bearer tokens, and dict keys
  containing `password` / `secret` / `token` / `auth` / `api_key` /
  `credential` / `session` / `cookie` / `private_key`. Optional
  Shannon-entropy detector (off by default).
- Two mask styles: `FORMAT_PRESERVING` (default — `j***@gmail.com`,
  `sk_live_****xyz`, `AK****PLE`) and `FULL_REDACTION`
  (`[REDACTED_<TYPE>]`).
- `block_secrets=True` raises `RedactlyBlockedError` at the call site and
  prevents the record from reaching any handler.
- `add_detector` and `add_masker` for user-supplied detection / masking
  callbacks. `custom_rules=[Rule(...)]` for regex-only rules.
- `telemetry_hook` — single callable invoked once per masked / blocked /
  allowed hit with a stable event shape (`type`, `action`, `key`, `source`,
  `detector`, `timestamp`).
- `dev_warnings=False` to silence the stderr warning blocks in noisy
  environments.
- `REDACTLY_DISABLED=1` env var (or `configure(enabled=False)`) for prod
  bypass; the filter returns in a single config lookup.
- Pure-Python, no native deps. Runtime requirements: `pydantic>=2`,
  `regex>=2024`. Tested on Python 3.13+.
- 81 tests, 100% line coverage, ruff / format / mypy strict all clean.

[Unreleased]: https://github.com/gupsho/redactly/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/gupsho/redactly/releases/tag/v0.1.1
[0.1.0]: https://github.com/gupsho/redactly/releases/tag/v0.1.0
