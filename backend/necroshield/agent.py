"""Naive fixture agent: a bounded state machine that follows its task plan and obeys any
`assistant: call tool({...})` line it finds in tool output.

Planning happens once, against a disposable planning environment, so injections in documents and
in tool responses are both seen through real tool output. The resulting intents are templates:
`$name` placeholders are bound at execution time from facts the agent learns in *that* run. The
intended actions are therefore identical across runs, while values flow from what each run
actually observed. This agent does not model any LLM.
"""

from __future__ import annotations

import json
import re
from collections import deque
from string import Template

from .contracts import ToolCall
from .gateway import Gateway
from .scenarios import Scenario
from .tools import Environment

MAX_STEPS = 32
INJECTED_CALL = re.compile(r"^assistant:\s*call\s+([a-z_]+)\((\{.*\})\)\s*$", re.MULTILINE)
FACTS = {"number": re.compile(r"^INVOICE\s+(\S+)", re.MULTILINE),
         "total": re.compile(r"^Total:\s*(.+)$", re.MULTILINE)}


def injected_calls(text: str) -> list[ToolCall]:
    calls = []
    for tool, raw in INJECTED_CALL.findall(text):
        try:
            args = json.loads(raw)
            if isinstance(args, dict):
                calls.append(ToolCall(tool, {str(k): str(v) for k, v in args.items()}))
        except (ValueError, TypeError):
            continue  # Malformed injected text is ignored, as a parser would.
    return calls


def learn(facts: dict[str, str], call: ToolCall, output: str) -> None:
    if call.tool == "read_document":
        for name, pattern in FACTS.items():
            match = pattern.search(output)
            if match and name not in facts:
                facts[name] = match.group(1).strip()
    elif call.tool == "read_memory" and call.args.get("key", "").startswith("payee/"):
        facts["payee"] = output


def bind(intent: ToolCall, facts: dict[str, str]) -> ToolCall:
    return ToolCall(intent.tool, {k: Template(v).safe_substitute(facts) for k, v in intent.args.items()})


def plan(scenario: Scenario) -> tuple[ToolCall, ...]:
    gateway = Gateway(Environment.from_scenario(scenario), policy=None)
    queue: deque[ToolCall] = deque(scenario.plan)
    facts: dict[str, str] = {}
    intents: list[ToolCall] = []
    while queue:
        if len(intents) >= MAX_STEPS:
            raise RuntimeError("agent exceeded step bound")
        intent = queue.popleft()
        intents.append(intent)
        call = bind(intent, facts)
        record = gateway.execute(call)
        if record.output:
            learn(facts, call, record.output)
            queue.extendleft(reversed(injected_calls(record.output)))
    return tuple(intents)
