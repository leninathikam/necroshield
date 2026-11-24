"""Bounded mock tools over a fresh in-memory environment. No tool touches disk, network, or processes."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Mapping

from .scenarios import Scenario

MAX_OUTPUT_CHARS = 8192
# Messages can only target addresses in the reserved, unroutable .invalid TLD (RFC 2606).
SINK_ADDRESS = re.compile(r"[a-z0-9._-]{1,64}@[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})*\.invalid")


class ToolError(Exception):
    pass


@dataclass
class Environment:
    documents: dict[str, str]
    customer_records: dict[str, str]
    reports: dict[str, str] = field(default_factory=dict)
    sink: list[dict[str, str]] = field(default_factory=list)
    invocations: list[str] = field(default_factory=list)
    documents_read: set[str] = field(default_factory=set)

    @classmethod
    def from_scenario(cls, scenario: Scenario) -> "Environment":
        return cls(documents=dict(scenario.documents), customer_records=dict(scenario.customer_records))


def _bounded(text: str) -> str:
    return text[:MAX_OUTPUT_CHARS]


def read_document(env: Environment, args: Mapping[str, str]) -> str:
    doc_id = args["doc_id"]
    if doc_id not in env.documents:
        raise ToolError(f"no such document: {doc_id}")
    env.documents_read.add(doc_id)
    return _bounded(env.documents[doc_id])


def write_report(env: Environment, args: Mapping[str, str]) -> str:
    env.reports[args["report_id"]] = _bounded(args["body"])
    return f"report {args['report_id']} written"


def send_message(env: Environment, args: Mapping[str, str]) -> str:
    to = args["to"]
    if not SINK_ADDRESS.fullmatch(to):
        raise ToolError("messages may only target the synthetic sink")
    attach = args.get("attach", "")
    if attach == "customer_records":
        body = "\n".join(env.customer_records.values())
    elif attach == "":
        body = args.get("body", "")
    else:
        raise ToolError(f"unknown attachment: {attach}")
    env.sink.append({"to": to, "body": _bounded(body)})
    return "message queued"


ToolFn = Callable[[Environment, Mapping[str, str]], str]

TOOLS: dict[str, ToolFn] = {
    "read_document": read_document,
    "write_report": write_report,
    "send_message": send_message,
}


def invoke(env: Environment, tool: str, args: Mapping[str, str]) -> str:
    fn = TOOLS.get(tool)
    if fn is None:
        raise ToolError(f"unknown tool: {tool}")
    env.invocations.append(tool)
    try:
        return fn(env, args)
    except KeyError as missing:
        raise ToolError(f"missing argument: {missing}") from None
