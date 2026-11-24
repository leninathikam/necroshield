"""Typed contracts shared by the arena core. Values are validated at construction and fail closed."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,63}")
MAX_ARG_CHARS = 4096
_FORBIDDEN_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\ud800-\udfff]")


class RunMode(str, Enum):
    BASELINE = "baseline"
    PROTECTED = "protected"


REPLAY_MODE = "deterministic_intent_replay"


def canonical_json(value: Any) -> str:
    """Stable JSON used for every digest and hash. Rejects NaN/Infinity and non-JSON types."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def require_identifier(value: object, what: str) -> str:
    if type(value) is not str or not IDENTIFIER.fullmatch(value):
        raise ValueError(f"invalid {what}: {value!r}")
    return value


def require_text(value: object, what: str, limit: int) -> str:
    """Exact str (no subclasses), bounded, and free of control characters (other than tab and
    newline) and lone surrogates, which cannot be encoded and so could not be hashed."""
    if type(value) is not str:
        raise TypeError(f"{what} must be str, got {type(value).__name__}")
    if len(value) > limit:
        raise ValueError(f"{what} exceeds {limit} characters")
    if _FORBIDDEN_CHARS.search(value):
        raise ValueError(f"{what} contains control characters or lone surrogates")
    return value


@dataclass(frozen=True)
class ToolCall:
    tool: str
    args: Mapping[str, str]

    def __post_init__(self) -> None:
        require_identifier(self.tool, "tool name")
        if not isinstance(self.args, Mapping):
            raise TypeError("tool arguments must be a mapping")
        clean = {require_identifier(k, "argument name"): require_text(v, f"argument {k}", MAX_ARG_CHARS)
                 for k, v in self.args.items()}
        if len(canonical_json(clean)) > MAX_ARG_CHARS:
            raise ValueError("tool arguments exceed size limit")
        object.__setattr__(self, "args", MappingProxyType(clean))

    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "args": dict(self.args)}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ToolCall":
        if set(data) != {"tool", "args"}:
            raise ValueError("tool call must have exactly 'tool' and 'args'")
        return cls(data["tool"], data["args"])


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    grant_id: str | None = None


@dataclass(frozen=True)
class DispatchRecord:
    """What happened to one intended call in one run."""

    call: ToolCall
    decision: Decision
    dispatched: bool
    output: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class Outcome:
    attack_succeeded: bool
    task_completed: bool
    observed_effects: tuple[str, ...] = field(default_factory=tuple)
