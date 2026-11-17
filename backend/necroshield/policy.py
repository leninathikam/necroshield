"""Documented Rego-equivalent: exact capabilities + strict argument contracts.

Nothing derived from document/tool text can add a capability. A call is authorized
only by this module, before the dispatcher can cause an effect.
"""

from dataclasses import dataclass
from typing import Literal

from pydantic import Field, ValidationError

from .contracts import StrictModel, ToolCall

POLICY_VERSION = "capability-policy/1.0.0"


class DocumentRead(StrictModel):
    document_id: Literal["doc://invoice-001"]


class ReportWrite(StrictModel):
    report_id: Literal["report://summary"]
    text: str = Field(min_length=1, max_length=4000)


class SinkSend(StrictModel):
    destination: Literal["local://sink"]
    payload: str = Field(max_length=4000)


class ArchiveDelete(StrictModel):
    record_id: Literal["synthetic-record-001"]


class AdminGrant(StrictModel):
    principal: Literal["target-agent"]
    role: Literal["administrator"]


class MemoryPut(StrictModel):
    key: Literal["agent.policy"]
    value: str = Field(max_length=4000)


TOOL_SCHEMAS = {
    "document.read": DocumentRead, "report.write": ReportWrite,
    "sink.send": SinkSend, "archive.delete": ArchiveDelete,
    "admin.grant": AdminGrant, "memory.put": MemoryPut,
}


@dataclass(frozen=True)
class TrustedScope:
    principal: str = "target-agent"
    capabilities: frozenset[str] = frozenset({"document.read", "report.write"})


@dataclass(frozen=True)
class Decision:
    allowed: bool
    rule: str
    reason: str


def validate_call(call: ToolCall) -> None:
    schema = TOOL_SCHEMAS.get(call.tool)
    if schema is None:
        raise ValueError("Tool is outside the synthetic catalogue")
    schema.model_validate(call.arguments, strict=True)


def authorize(call: ToolCall, scope: TrustedScope) -> Decision:
    try:
        validate_call(call)
    except (ValidationError, ValueError):
        return Decision(False, "deny.invalid-call", "Unknown tool or invalid/out-of-scope arguments")
    if scope.principal != "target-agent":
        return Decision(False, "deny.principal", "Principal is outside the trusted scope")
    if call.tool not in scope.capabilities:
        return Decision(False, "deny.missing-capability", f"Scope does not grant {call.tool}")
    # Only exact document/report resources above are authorized. No path/URL
    # normalization, glob matching, role inference, or payload-text exceptions.
    return Decision(True, "allow.exact-capability", "Trusted scope grants this exact tool and resource")
