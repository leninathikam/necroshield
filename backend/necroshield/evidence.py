"""Redaction and hash-linked event chains.

Integrity limit: the chain detects edits, reordering, insertion, and removal of individual events
relative to the recorded head. Anyone able to rewrite an entire export can recompute every hash,
so the chain is not proof of authorship. There is no signature.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .contracts import canonical_json

GENESIS = "0" * 64
EXPORT_FORMAT = "necroshield.pair/2"

# Synthetic secret shapes used by fixtures. Sink addresses (*.invalid other than example.invalid)
# and canary tokens are kept: they are the observable evidence of a leak, not secrets.
_REDACTIONS = (
    (re.compile(r"sk-synthetic-[A-Za-z0-9_-]+", re.IGNORECASE), "[REDACTED:api_key]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@example\.invalid", re.IGNORECASE), "[REDACTED:email]"),
)


def is_redactable(text: str) -> bool:
    """True if redaction would change this text. Policy scope values, check parameters, and
    initial memory must not be redactable, so evidence and enforcement see the same values."""
    return any(pattern.search(text) for pattern, _ in _REDACTIONS)


def redact(value: Any) -> Any:
    """Redact every string in a JSON-like value, including dict keys."""
    if isinstance(value, str):
        for pattern, replacement in _REDACTIONS:
            value = pattern.sub(replacement, value)
        return value
    if isinstance(value, dict):
        return {redact(k): redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise TypeError(f"evidence values must be JSON-native, got {type(value).__name__}")


def _reject_floats(value: Any) -> None:
    """Hashed events carry no floats: float formatting is the least portable part of JSON, and a
    third-party verifier in another language must reproduce every hash exactly."""
    if isinstance(value, float):
        raise TypeError("evidence values must be JSON-native without floats, got float")
    if isinstance(value, dict):
        for v in value.values():
            _reject_floats(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _reject_floats(v)


def link(prev_hash: str, body: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + canonical_json(body)).encode()).hexdigest()


class EventChain:
    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.events: list[dict[str, Any]] = []
        self.head = GENESIS

    def append(self, kind: str, data: dict[str, Any]) -> dict[str, Any]:
        _reject_floats(data)
        body = redact({"run_id": self.run_id, "seq": len(self.events), "kind": kind, "data": data})
        body["prev_hash"] = self.head
        body["hash"] = link(self.head, body)
        self.head = body["hash"]
        self.events.append(body)
        return body
