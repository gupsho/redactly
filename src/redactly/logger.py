from __future__ import annotations

import copy
import logging
import os
from typing import Any

from .config import get_config
from .detector import scan_mapping, scan_string
from .exceptions import RedactlyBlockedError
from .masker import apply_to_string, apply_to_structure
from .policy import decide
from .rules import Action, Hit
from .warnings import emit

_FILTER_ATTR = "_redactly_filter_attached"

# Snapshot the set of attributes logging.LogRecord sets on itself, so we can
# tell which keys on record.__dict__ came from the user's `extra={...}` kwarg.
_STD_LOGRECORD_ATTRS: frozenset[str] = frozenset(logging.makeLogRecord({}).__dict__.keys()) | {
    "message",
    "asctime",
}


def _collect_extras(record: logging.LogRecord) -> dict[str, Any]:
    return {
        k: v
        for k, v in record.__dict__.items()
        if k not in _STD_LOGRECORD_ATTRS and not k.startswith("_")
    }


class RedactlyFilter(logging.Filter):
    """Intercepts LogRecords, scans for sensitive data, masks or blocks."""

    def filter(self, record: logging.LogRecord) -> bool:
        cfg = get_config()
        if not cfg.is_enabled():
            return True

        # --- 1. Scan structured sources (read-only). ---
        structured_msg: Any = None
        msg_struct_hits: list[Hit] = []
        if isinstance(record.msg, (dict, list, tuple)):
            structured_msg = record.msg
            msg_struct_hits = scan_mapping(structured_msg)

        args_ref: Any = None
        args_hits: list[Hit] = []
        if isinstance(record.args, dict):
            args_ref = record.args
            args_hits = scan_mapping(args_ref)
        elif isinstance(record.args, tuple):
            for i, a in enumerate(record.args):
                if isinstance(a, (dict, list, tuple)):
                    args_ref = record.args
                    args_hits.extend(scan_mapping(a, (i,)))

        extras_ref = _collect_extras(record)
        extras_hits = scan_mapping(extras_ref) if extras_ref else []

        # --- 2. Render the message — using args pre-masked for structural
        # hits — so dict-key redactions appear in the formatted output.
        # Then scan the rendered text for content-level (regex) hits. ---
        final_msg: str | None = None
        msg_text_hits: list[Hit] = []
        struct_action: dict[int, Action] = {}

        if structured_msg is None:
            rendering_args = record.args
            if args_hits:
                struct_action = {id(h): decide(h) for h in args_hits}
                args_mask_pre = [h for h in args_hits if struct_action[id(h)] == Action.MASK]
                if args_mask_pre:
                    masked = _deep_copy_args(record.args, args_ref)
                    apply_to_structure(masked, args_mask_pre)
                    rendering_args = tuple(masked) if isinstance(args_ref, tuple) else masked
            try:
                final_msg = str(record.msg) % rendering_args if rendering_args else str(record.msg)
            except Exception:
                return True
            msg_text_hits = scan_string(final_msg)

        all_hits = msg_struct_hits + args_hits + extras_hits + msg_text_hits
        if not all_hits:
            return True

        # --- 3. Decide, warn, optionally block. ---
        action_by_id: dict[int, Action] = dict(struct_action)
        for h in msg_struct_hits + extras_hits + msg_text_hits:
            action_by_id[id(h)] = decide(h)

        warned: set[tuple[str, str]] = set()
        blocking_hit: Hit | None = None
        for h in all_hits:
            action = action_by_id[id(h)]
            if action == Action.ALLOW:
                continue
            key = (h.type.value, h.value)
            if key not in warned:
                emit(h, action=action, pathname=record.pathname, lineno=record.lineno)
                warned.add(key)
            if action == Action.BLOCK and blocking_hit is None:
                blocking_hit = h

        if blocking_hit is not None:
            raise RedactlyBlockedError(
                hit_type=blocking_hit.type.value,
                key=blocking_hit.key,
                location=f"{os.path.basename(record.pathname)}:{record.lineno}",
            )

        # --- 4. Apply masks. ---
        msg_struct_mask = [h for h in msg_struct_hits if action_by_id[id(h)] == Action.MASK]
        args_mask = [h for h in args_hits if action_by_id[id(h)] == Action.MASK]
        msg_text_mask = [h for h in msg_text_hits if action_by_id[id(h)] == Action.MASK]
        extras_mask = [h for h in extras_hits if action_by_id[id(h)] == Action.MASK]

        if structured_msg is not None and msg_struct_mask:
            msg_copy = copy.deepcopy(structured_msg)
            apply_to_structure(msg_copy, msg_struct_mask)
            record.msg = msg_copy
            record.args = None
        elif final_msg is not None and (msg_text_mask or args_mask):
            # final_msg was rendered from already-masked args, so installing
            # it as record.msg captures both structural and content masking.
            record.msg = apply_to_string(final_msg, msg_text_mask)
            record.args = None

        if extras_mask:
            extras_copy = copy.deepcopy(extras_ref)
            apply_to_structure(extras_copy, extras_mask)
            for name, value in extras_copy.items():
                setattr(record, name, value)

        return True


def _deep_copy_args(args: Any, args_ref: Any) -> Any:
    """Deep-copy args into a mutable form for structural masking. Tuples
    become lists so apply_to_structure can mutate slot values in place.
    """
    if isinstance(args_ref, tuple):
        return copy.deepcopy(list(args))
    return copy.deepcopy(args)


def get_logger(name: str) -> logging.Logger:
    """Return a stdlib Logger with a RedactlyFilter attached (idempotent)."""
    logger = logging.getLogger(name)
    if not getattr(logger, _FILTER_ATTR, False):
        logger.addFilter(RedactlyFilter())
        setattr(logger, _FILTER_ATTR, True)
    return logger
