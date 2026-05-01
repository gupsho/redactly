from __future__ import annotations

import logging

import pytest

import redactly
from redactly.detector import _clear_extra_detectors
from redactly.masker import _clear_extra_maskers


@pytest.fixture(autouse=True)
def _reset_redactly():
    redactly.reset_config()
    _clear_extra_detectors()
    _clear_extra_maskers()
    # Wipe the logging cache so each test gets a fresh logger with a fresh filter.
    logging.Logger.manager.loggerDict.clear()
    yield
    redactly.reset_config()
    _clear_extra_detectors()
    _clear_extra_maskers()


@pytest.fixture
def captured_logs():
    """Attach a list-backed handler to the root logger and return the record list."""
    records: list[logging.LogRecord] = []

    class _ListHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _ListHandler(level=logging.DEBUG)
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    yield records
    root.removeHandler(handler)
