"""Canonical event hashes and structural redaction for portable evidence."""

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from .contracts import Event, RunPair

GENESIS = "0" * 64
_SYNTHETIC_SECRET = re.compile(r"SYNTHETIC-SECRET-[A-Za-z0-9_-]+")
_TOKEN = re.compile(r"(?i)\b(?:sk-[A-Za-z0-9_-]{8,}|bearer\s+[A-Za-z0-9._-]+)")
_SENSITIVE_KEYS = {"secret", "token", "password", "authorization", "apikey", "payload",
                   "accesstoken", "refreshtoken", "clientsecret", "privatekey", "credential",
                   "credentials", "passwd", "sessiontoken", "awsaccesskeyid", "awssecretaccesskey",
                   "cookie", "setcookie"}


def _sensitive_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    return normalized in _SENSITIVE_KEYS or normalized.endswith(("secret", "token", "password", "apikey"))


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode()).hexdigest()


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: "[REDACTED]" if _sensitive_key(key) else redact(item)
                for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _TOKEN.sub("[REDACTED]", _SYNTHETIC_SECRET.sub("[REDACTED]", value))
    return value


class Trace:
    def __init__(self) -> None:
        self.events: list[Event] = []

    def append(self, *, kind: str, reason: str, message: str, tool: str | None = None,
               decision: str | None = None, arguments: dict | None = None,
               result: dict | None = None) -> None:
        body = {"sequence": len(self.events) + 1, "kind": kind, "tool": tool,
                "decision": decision, "reason": reason, "message": message,
                "arguments": redact(arguments), "result": redact(result),
                "previous_hash": self.events[-1].hash if self.events else GENESIS,
                "timestamp": datetime.now(timezone.utc).isoformat()}
        self.events.append(Event.model_validate({**body, "hash": canonical_hash(body)}))


def verify_chain(events: list[Event]) -> bool:
    previous = GENESIS
    for index, event in enumerate(events, 1):
        body = event.model_dump(mode="json", exclude={"hash"})
        # Pydantic serializes UTC as Z; canonicalize to the stored +00:00 format.
        body["timestamp"] = event.timestamp.isoformat()
        if event.sequence != index or event.previous_hash != previous:
            return False
        if canonical_hash(body) != event.hash:
            return False
        previous = event.hash
    return True


def export_pair(pair: RunPair) -> dict[str, Any]:
    data = redact(pair.model_dump(mode="json"))
    data["evidence"] = {
        "schema_version": "necroshield-evidence/1",
        "redaction": "before-event-hashing; sensitive keys and recognized token patterns",
        "hash_algorithm": "sha256-canonical-json",
        "baseline_chain_valid": verify_chain(pair.baseline.events),
        "protected_chain_valid": verify_chain(pair.protected.events),
        "limits": "Hash chains detect mutation; they do not prove authorship or provide external notarization.",
    }
    return {**data, "export_digest": canonical_hash(data)}
