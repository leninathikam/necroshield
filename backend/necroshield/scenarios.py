"""Scenario, policy, and outcome-check types. Everything is immutable and validated at construction:
an invalid scenario or policy raises instead of running with a weaker definition (fail closed)."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from .contracts import ToolCall, canonical_json, require_identifier, require_text
from .tools import TOOL_NAMES, TOOLS

MAX_DOCUMENT_CHARS = 16384
VERSION = re.compile(r"\d+\.\d+\.\d+")
RESOURCE_ID = re.compile(r"[a-z0-9][a-z0-9_./-]{0,127}")


def _frozen_text_map(value: Mapping[str, str], what: str, key_pattern: re.Pattern) -> Mapping[str, str]:
    out = {}
    for key, text in value.items():
        if type(key) is not str or not key_pattern.fullmatch(key):
            raise ValueError(f"invalid {what} key: {key!r}")
        out[key] = require_text(text, f"{what} {key}", MAX_DOCUMENT_CHARS)
    return MappingProxyType(out)


@dataclass(frozen=True)
class Grant:
    """Allows one tool. Every argument must be listed: a tuple of allowed values, or None for any
    bounded string. Unlisted arguments are denied."""

    grant_id: str
    tool: str
    allowed_args: Mapping[str, tuple[str, ...] | None]

    def __post_init__(self) -> None:
        require_identifier(self.grant_id.replace("-", "_"), "grant id")
        if self.tool not in TOOL_NAMES:
            raise ValueError(f"grant {self.grant_id} names unknown tool {self.tool!r}")
        spec = TOOLS[self.tool]
        clean: dict[str, tuple[str, ...] | None] = {}
        for name, values in self.allowed_args.items():
            if name not in spec.required + spec.optional:
                raise ValueError(f"grant {self.grant_id}: {self.tool} has no argument {name!r}")
            if values is None:
                clean[name] = None
            else:
                values = tuple(values)
                if not values or any(type(v) is not str for v in values):
                    raise ValueError(f"grant {self.grant_id}: {name} needs a non-empty list of strings or null")
                clean[name] = tuple(sorted(set(values)))
        if not set(spec.required) <= set(clean):
            raise ValueError(f"grant {self.grant_id}: must constrain required arguments {spec.required}")
        object.__setattr__(self, "allowed_args", MappingProxyType(clean))

    def to_dict(self) -> dict[str, Any]:
        return {"grant_id": self.grant_id, "tool": self.tool,
                "allowed_args": {k: (list(v) if v is not None else None) for k, v in self.allowed_args.items()}}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Grant":
        if set(data) != {"grant_id", "tool", "allowed_args"}:
            raise ValueError("grant must have exactly grant_id, tool, allowed_args")
        if not isinstance(data["allowed_args"], Mapping):
            raise ValueError("allowed_args must be an object")
        return cls(data["grant_id"], data["tool"], dict(data["allowed_args"]))


@dataclass(frozen=True)
class Policy:
    version: str
    grants: tuple[Grant, ...]

    def __post_init__(self) -> None:
        require_text(self.version, "policy version", 64)
        object.__setattr__(self, "grants", tuple(self.grants))
        ids = [g.grant_id for g in self.grants]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate grant ids")
        if not all(isinstance(g, Grant) for g in self.grants):
            raise TypeError("grants must be Grant instances")

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "grants": [g.to_dict() for g in self.grants]}

    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self.to_dict()).encode()).hexdigest()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Policy":
        if set(data) != {"version", "grants"} or not isinstance(data["grants"], list):
            raise ValueError("policy must have exactly version and a grants list")
        return cls(data["version"], tuple(Grant.from_dict(g) for g in data["grants"]))


# Check kinds, each tied to the tool whose execution can produce the effect. The standalone
# verifier uses the same table to reject claimed effects that no dispatched call could produce.
CHECK_PRODUCERS: Mapping[str, tuple[str, ...]] = MappingProxyType({
    "sink_contains": ("send_message",),
    "resource_read": ("read_document", "get_customer_record", "read_memory"),
    "memory_equals": ("write_memory",),
    "report_equals": ("write_report",),
})
CHECK_PARAMS: Mapping[str, frozenset[str]] = MappingProxyType({
    "sink_contains": frozenset({"value", "to", "exclude_to"}),
    "resource_read": frozenset({"resource"}),
    "memory_equals": frozenset({"key", "value"}),
    "report_equals": frozenset({"report_id", "text"}),
})


@dataclass(frozen=True)
class Check:
    kind: str
    params: Mapping[str, str]
    description: str

    def __post_init__(self) -> None:
        if self.kind not in CHECK_PARAMS:
            raise ValueError(f"unknown check kind: {self.kind}")
        required = CHECK_PARAMS[self.kind] - {"to", "exclude_to"}
        if not required <= set(self.params) <= CHECK_PARAMS[self.kind]:
            raise ValueError(f"check {self.kind} needs {sorted(required)}")
        clean = {k: require_text(v, f"check {k}", 1024) for k, v in self.params.items()}
        object.__setattr__(self, "params", MappingProxyType(clean))

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "params": dict(self.params), "description": self.description}


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    version: str
    kind: str  # "attack" or "control"
    title: str
    attack_class: str
    trusted_task: str
    attacker_surface: str
    forbidden_behavior: str
    documents: Mapping[str, str]
    customer_records: Mapping[str, str]
    memory: Mapping[str, str]
    plan: tuple[ToolCall, ...]  # the legitimate task; $placeholders are filled from tool outputs
    attack_checks: tuple[Check, ...]
    task_checks: tuple[Check, ...]
    policy: Policy
    canaries: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        require_identifier(self.scenario_id, "scenario id")
        if type(self.version) is not str or not VERSION.fullmatch(self.version):
            raise ValueError(f"scenario version must be MAJOR.MINOR.PATCH: {self.version!r}")
        if self.kind not in ("attack", "control"):
            raise ValueError("kind must be attack or control")
        for name in ("title", "attack_class", "trusted_task", "attacker_surface", "forbidden_behavior"):
            require_text(getattr(self, name), name, 1024)
        object.__setattr__(self, "documents", _frozen_text_map(self.documents, "document", RESOURCE_ID))
        object.__setattr__(self, "customer_records", _frozen_text_map(self.customer_records, "customer", RESOURCE_ID))
        object.__setattr__(self, "memory", _frozen_text_map(self.memory, "memory", RESOURCE_ID))
        for name in ("plan", "attack_checks", "task_checks", "canaries"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        if not self.plan or any(c.tool not in TOOL_NAMES for c in self.plan):
            raise ValueError("plan must be non-empty and use known tools")
        if not self.task_checks:
            raise ValueError("every scenario needs a legitimate-task check")
        if (self.kind == "attack") != bool(self.attack_checks):
            raise ValueError("attack scenarios need attack checks; control scenarios must have none")

    @property
    def allowed_tools(self) -> tuple[str, ...]:
        return tuple(sorted({g.tool for g in self.policy.grants}))

    def manifest(self) -> dict[str, Any]:
        """Full, canonical definition. The digest covers every field."""
        return {
            "scenario_id": self.scenario_id, "version": self.version, "kind": self.kind,
            "title": self.title, "attack_class": self.attack_class, "trusted_task": self.trusted_task,
            "attacker_surface": self.attacker_surface, "forbidden_behavior": self.forbidden_behavior,
            "documents": dict(self.documents), "customer_records": dict(self.customer_records),
            "memory": dict(self.memory), "plan": [c.to_dict() for c in self.plan],
            "attack_checks": [c.to_dict() for c in self.attack_checks],
            "task_checks": [c.to_dict() for c in self.task_checks],
            "policy": self.policy.to_dict(), "canaries": list(self.canaries),
        }

    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self.manifest()).encode()).hexdigest()
