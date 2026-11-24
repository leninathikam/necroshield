"""Redaction and hash-linked event chains.

Integrity limit: the chain detects edits, reordering, insertion, and removal of individual events
relative to the recorded head. Anyone able to rewrite an entire export can recompute every hash,
so the chain is not proof of authorship.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .contracts import canonical_json

GENESIS = "0" * 64
EXPORT_FORMAT = "necroshield.pair/1"

_REDACTIONS = (
    (re.compile(r"sk-synthetic-[A-Za-z0-9]+"), "[REDACTED:api_key]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@example\.invalid"), "[REDACTED:email]"),
)


def redact(value: Any) -> Any:
    if isinstance(value, str):
        for pattern, replacement in _REDACTIONS:
            value = pattern.sub(replacement, value)
        return value
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value


def link(prev_hash: str, body: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + canonical_json(body)).encode()).hexdigest()


class EventChain:
    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.events: list[dict[str, Any]] = []
        self.head = GENESIS

    def append(self, kind: str, data: dict[str, Any]) -> dict[str, Any]:
        body = redact({"run_id": self.run_id, "seq": len(self.events), "kind": kind, "data": data})
        body["prev_hash"] = self.head
        body["hash"] = link(self.head, {k: v for k, v in body.items() if k != "hash"})
        self.head = body["hash"]
        self.events.append(body)
        return body
