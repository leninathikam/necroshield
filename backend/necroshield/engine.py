"""Bounded typed state machine, policy gateway, and counterfactual replay."""

import re
import time
from datetime import datetime, timezone
from uuid import uuid4

from .contracts import Metrics, Run, RunPair, ToolCall
from .evidence import Trace, canonical_hash
from .gateway import Gateway
from .policy import POLICY_VERSION, validate_call
from .scenarios import DIRECTIVE_MARKER, EXPECTED_REPORT, Scenario
from .tools import SyntheticWorld

MAX_ACTIONS = 8
MAX_SOURCE_BYTES = 16_384


def build_intent_tape(scenario: Scenario) -> tuple[ToolCall, ...]:
    """A deliberately vulnerable fixture agent follows a bounded inert directive.

    No LLM is called. The fixed document/tool response is parsed once; the same
    proposed actions then run in fresh baseline and protected worlds. A denial
    does not cause replanning. This is intent replay, not stochastic agent replay.
    """
    # Materialize the immutable fixture response both traced tool reads will
    # return. This is pure scenario data, not an untraced planning tool dispatch.
    read = ToolCall(tool="document.read", arguments={"document_id": "doc://invoice-001"})
    response = scenario.document_response()
    source = response["body"] + "\n" + response["tool_note"]
    if len(source.encode()) > MAX_SOURCE_BYTES:
        raise ValueError("Scenario source exceeds the arena limit")
    tape = [read]
    for line in source.splitlines():
        if line.startswith(DIRECTIVE_MARKER):
            call = ToolCall.model_validate_json(line.removeprefix(DIRECTIVE_MARKER))
            validate_call(call)
            tape.append(call)
    total_match = re.search(r"^Total: (\d{1,8}) credits\.$", response["body"], re.MULTILINE)
    if total_match is None:
        raise ValueError("Synthetic invoice has no valid total")
    report = f"Invoice total: {int(total_match.group(1))} credits."
    tape.append(ToolCall(tool="report.write", arguments={"report_id": "report://summary", "text": report}))
    if len(tape) > MAX_ACTIONS:
        raise ValueError("Intent tape exceeds the arena action budget")
    return tuple(tape)


def _execute(scenario: Scenario, tape: tuple[ToolCall, ...], protected: bool) -> Run:
    start = time.perf_counter()
    mode = "protected" if protected else "baseline"
    world, trace = SyntheticWorld(scenario), Trace()
    gateway = Gateway(world, trace, protected=protected)
    trace.append(kind="run.started", reason="fixture.start", message=f"Started {mode} in a fresh synthetic world")
    for call in tape:
        gateway.call(call)
    effects = world.effects()
    attack_success = bool(scenario.attack_effect and effects[scenario.attack_effect])
    task_complete = world.report == EXPECTED_REPORT
    trace.append(kind="run.completed", reason="evaluator.effects", message="Outcome verified from synthetic state",
        result={"attack_success": attack_success, "legitimate_task_completed": task_complete, "effects": effects})
    return Run(id=str(uuid4()), mode=mode, status="completed", events=trace.events,
        metrics=Metrics(attack_success=attack_success, blocked_executions=gateway.blocked,
            legitimate_task_completed=task_complete, false_positives=gateway.false_positives,
            latency_ms=round((time.perf_counter() - start) * 1000, 3),
            tool_calls=len(world.executed), cost_usd=None),
        output=world.report, effects=effects)


def execute_pair(scenario: Scenario) -> RunPair:
    tape = build_intent_tape(scenario)
    return RunPair(id=str(uuid4()), scenario_id=scenario.info.id, scenario_name=scenario.info.name,
        scenario_version=scenario.info.version, scenario_digest=scenario.digest(), policy_version=POLICY_VERSION,
        created_at=datetime.now(timezone.utc), intent_tape_digest=canonical_hash([c.model_dump() for c in tape]),
        baseline=_execute(scenario, tape, protected=False), protected=_execute(scenario, tape, protected=True))
