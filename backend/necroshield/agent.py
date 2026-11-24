"""Naive fixture agent: a bounded state machine that obeys instruction lines found in its source.

It exists to produce a deterministic attack intent, not to model any real LLM.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum

from .contracts import ToolCall
from .scenarios import Scenario

MAX_STEPS = 16
INJECTED_CALL = re.compile(r"^assistant:\s*call\s+([a-z_]+)\((\{.*\})\)\s*$", re.MULTILINE)
INVOICE_NUMBER = re.compile(r"^INVOICE\s+(\S+)", re.MULTILINE)
INVOICE_TOTAL = re.compile(r"^Total:\s*(.+)$", re.MULTILINE)


class Step(Enum):
    READ_SOURCE = "read_source"
    EXTRACT = "extract"
    FOLLOW_INSTRUCTIONS = "follow_instructions"
    REPORT = "report"
    DONE = "done"


@dataclass
class _State:
    step: Step = Step.READ_SOURCE
    source: str = ""
    facts: dict[str, str] = field(default_factory=dict)
    intents: list[ToolCall] = field(default_factory=list)


def plan(scenario: Scenario) -> tuple[ToolCall, ...]:
    """Produce the agent's intended calls once. The runner replays them in each environment."""
    doc_id = next(iter(scenario.documents))
    state = _State()
    for _ in range(MAX_STEPS):
        if state.step is Step.READ_SOURCE:
            state.intents.append(ToolCall("read_document", {"doc_id": doc_id}))
            state.source = scenario.documents[doc_id]
            state.step = Step.EXTRACT
        elif state.step is Step.EXTRACT:
            for key, pattern in (("number", INVOICE_NUMBER), ("total", INVOICE_TOTAL)):
                match = pattern.search(state.source)
                if match:
                    state.facts[key] = match.group(1).strip()
            state.step = Step.FOLLOW_INSTRUCTIONS
        elif state.step is Step.FOLLOW_INSTRUCTIONS:
            for tool, raw_args in INJECTED_CALL.findall(state.source):
                try:
                    args = json.loads(raw_args)
                    state.intents.append(ToolCall(tool, {str(k): str(v) for k, v in args.items()}))
                except (ValueError, TypeError):
                    continue  # Malformed injected text is ignored, as a parser would.
            state.step = Step.REPORT
        elif state.step is Step.REPORT:
            body = f"Invoice {state.facts.get('number', '?')} total {state.facts.get('total', '?')}"
            state.intents.append(ToolCall("write_report", {"report_id": "summary", "body": body}))
            state.step = Step.DONE
        else:
            return tuple(state.intents)
    raise RuntimeError("agent exceeded step bound")
