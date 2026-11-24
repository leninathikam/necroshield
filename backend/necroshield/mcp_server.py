"""MCP sandbox built on the official Model Context Protocol SDK.

Each server instance owns one fresh synthetic environment. Every tool handler routes through a
Gateway, so in protected mode the default-deny policy is evaluated before tool code runs, and a
denied call returns an MCP error result without side effects.

Run over stdio:  python -m necroshield.mcp_server SCENARIO [--baseline]
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session

from . import agent
from .catalog import REGISTRY, get_scenario
from .contracts import DispatchRecord, ToolCall
from .evaluator import evaluate_outcome
from .evidence import redact
from .gateway import Gateway
from .scenarios import Policy, Scenario
from .tools import TOOLS, Environment


class PolicyDenied(Exception):
    pass


@dataclass
class Sandbox:
    scenario: Scenario
    gateway: Gateway
    server: FastMCP
    records: list[DispatchRecord] = field(default_factory=list)


def build_sandbox(scenario: Scenario, protected: bool = True, policy: Policy | None = None) -> Sandbox:
    env = Environment.from_scenario(scenario)
    gateway = Gateway(env, (policy or scenario.policy) if protected else None)
    server = FastMCP("necroshield-sandbox")
    sandbox = Sandbox(scenario, gateway, server)

    def dispatch(tool: str, **args: str | None) -> str:
        call = ToolCall(tool, {k: v for k, v in args.items() if v is not None})
        record = gateway.execute(call)
        sandbox.records.append(record)
        if not record.decision.allowed:
            raise PolicyDenied(f"denied before dispatch: {record.decision.reason}")
        if record.error:
            raise RuntimeError(record.error)
        return record.output or ""

    @server.tool(description=TOOLS["read_document"].description)
    def read_document(path: str) -> str:
        return dispatch("read_document", path=path)

    @server.tool(description=TOOLS["get_customer_record"].description)
    def get_customer_record(customer_id: str) -> str:
        return dispatch("get_customer_record", customer_id=customer_id)

    @server.tool(description=TOOLS["write_report"].description)
    def write_report(report_id: str, body: str) -> str:
        return dispatch("write_report", report_id=report_id, body=body)

    @server.tool(description=TOOLS["send_message"].description)
    def send_message(to: str, body: str | None = None, attach: str | None = None) -> str:
        return dispatch("send_message", to=to, body=body, attach=attach)

    @server.tool(description=TOOLS["read_memory"].description)
    def read_memory(key: str) -> str:
        return dispatch("read_memory", key=key)

    @server.tool(description=TOOLS["write_memory"].description)
    def write_memory(key: str, value: str) -> str:
        return dispatch("write_memory", key=key, value=value)

    return sandbox


def _text(result: Any) -> str:
    return "\n".join(getattr(part, "text", "") for part in result.content)


async def replay_over_mcp(scenario: Scenario, protected: bool, policy: Policy | None = None) -> dict[str, Any]:
    """Send the fixture agent's intended calls to the sandbox through a real MCP client session
    (official SDK, in-memory transport), binding placeholders from MCP responses."""
    sandbox = build_sandbox(scenario, protected, policy)
    intents = agent.plan(scenario)
    transcript: list[dict[str, Any]] = []
    facts: dict[str, str] = {}
    async with create_connected_server_and_client_session(sandbox.server._mcp_server) as client:
        listed = await client.list_tools()
        for intent in intents:
            call = agent.bind(intent, facts)
            before = len(sandbox.records)
            result = await client.call_tool(call.tool, dict(call.args))
            text = _text(result)
            record = sandbox.records[before] if len(sandbox.records) > before else None
            if not result.isError:
                agent.learn(facts, call, text)
            transcript.append({
                "tool": call.tool, "args": dict(call.args), "is_error": bool(result.isError), "response": text,
                "allowed": record.decision.allowed if record else None,
                "reason": record.decision.reason if record else "rejected by MCP before reaching the gateway",
                "dispatched": record.dispatched if record else False,
            })
    outcome = evaluate_outcome(scenario, sandbox.gateway.env)
    return redact({
        "transport": "mcp in-memory session (official SDK)",
        "mode": "protected" if protected else "baseline",
        "scenario_id": scenario.scenario_id,
        "tools_listed": sorted(t.name for t in listed.tools),
        "transcript": transcript,
        "outcome": {"attack_succeeded": outcome.attack_succeeded, "task_completed": outcome.task_completed,
                    "observed_effects": list(outcome.observed_effects)},
    })


def main() -> None:
    parser = argparse.ArgumentParser(prog="necroshield.mcp_server")
    parser.add_argument("scenario", choices=sorted(REGISTRY))
    parser.add_argument("--baseline", action="store_true", help="disable policy enforcement")
    args = parser.parse_args()
    build_sandbox(get_scenario(args.scenario), protected=not args.baseline).server.run("stdio")


if __name__ == "__main__":
    main()

