"""Typed contracts shared by the arena core. Values are validated at construction."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
MAX_ARG_CHARS = 4096


class RunMode(str, Enum):
    BASELINE = "baseline"
    PROTECTED = "protected"


REPLAY_MODE = "deterministic_intent_replay"


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class ToolCall:
    tool: str
    args: Mapping[str, str]

    def __post_init__(self) -> None:
        if not TOOL_NAME.fullmatch(self.tool):
            raise ValueError(f"invalid tool name: {self.tool!r}")
        if not all(isinstance(k, str) and isinstance(v, str) for k, v in self.args.items()):
            raise TypeError("tool arguments must be str -> str")
        if len(canonical_json(dict(self.args))) > MAX_ARG_CHARS:
            raise ValueError("tool arguments exceed size limit")
        object.__setattr__(self, "args", MappingProxyType(dict(self.args)))

    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "args": dict(self.args)}


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
