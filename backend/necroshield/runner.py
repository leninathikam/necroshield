"""Paired baseline/protected execution of one scenario's intended calls."""

from __future__ import annotations

import copy
import hashlib
import uuid
from dataclasses import dataclass
from typing import Any

from . import agent
from .contracts import REPLAY_MODE, Decision, DispatchRecord, Outcome, RunMode, ToolCall, canonical_json
from .evaluator import evaluate_outcome
from .evidence import EXPORT_FORMAT, EventChain, redact
from .policy import evaluate
from .scenarios import Scenario
from .tools import Environment, ToolError, invoke

_UNCHECKED = Decision(True, "baseline: no policy enforcement")


def redacted_intents(intents: tuple[ToolCall, ...]) -> list[dict[str, Any]]:
    """The form in which intents appear in evidence. Raw intents never leave the process."""
    return redact([c.to_dict() for c in intents])


def intents_digest(intents: tuple[ToolCall, ...]) -> str:
    return hashlib.sha256(canonical_json(redacted_intents(intents)).encode()).hexdigest()


@dataclass(frozen=True)
class RunResult:
    run_id: str
    mode: RunMode
    records: tuple[DispatchRecord, ...]
    outcome: Outcome
    events: tuple[dict[str, Any], ...]
    head: str

    def export(self) -> dict[str, Any]:
        # The exported outcome is the chained run_completed data, so it is redacted and hash-bound.
        return {"run_id": self.run_id, "mode": self.mode.value, "outcome": self.events[-1]["data"],
                "head": self.head, "events": list(self.events)}


@dataclass(frozen=True)
class PairResult:
    pair_id: str
    scenario: Scenario
    intents: tuple[ToolCall, ...]
    baseline: RunResult
    protected: RunResult

    def export(self) -> dict[str, Any]:
        s = self.scenario
        return copy.deepcopy({
            "format": EXPORT_FORMAT,
            "pair_id": self.pair_id,
            "replay_mode": REPLAY_MODE,
            "scenario": {"id": s.scenario_id, "version": s.version, "kind": s.kind, "digest": s.digest()},
            "policy": {"digest": s.policy.digest(), **s.policy.to_dict()},
            "intents": redacted_intents(self.intents),
            "runs": [self.baseline.export(), self.protected.export()],
        })


def _dispatch(env: Environment, call: ToolCall, decision: Decision) -> DispatchRecord:
    if not decision.allowed:
        return DispatchRecord(call, decision, dispatched=False)
    try:
        return DispatchRecord(call, decision, dispatched=True, output=invoke(env, call.tool, call.args))
    except ToolError as exc:
        return DispatchRecord(call, decision, dispatched=True, error=str(exc))
    except Exception as exc:  # A faulty tool must not abort the run or skip its evidence event.
        return DispatchRecord(call, decision, dispatched=True, error=f"tool fault: {type(exc).__name__}")


def run_once(scenario: Scenario, intents: tuple[ToolCall, ...], mode: RunMode, pair_id: str = "") -> RunResult:
    run_id = str(uuid.uuid4())
    env = Environment.from_scenario(scenario)
    chain = EventChain(run_id)
    chain.append("run_started", {
        "pair_id": pair_id, "mode": mode.value, "replay_mode": REPLAY_MODE,
        "scenario_id": scenario.scenario_id, "scenario_version": scenario.version,
        "scenario_digest": scenario.digest(), "policy_digest": scenario.policy.digest(),
        "intents_digest": intents_digest(intents),
    })
    records = []
    for index, call in enumerate(intents):
        decision = evaluate(scenario.policy, call) if mode is RunMode.PROTECTED else _UNCHECKED
        record = _dispatch(env, call, decision)
        records.append(record)
        chain.append("tool_call", {
            "intent_index": index, **call.to_dict(), "allowed": decision.allowed, "reason": decision.reason,
            "grant_id": decision.grant_id, "dispatched": record.dispatched,
            "output": record.output, "error": record.error,
        })
    outcome = evaluate_outcome(scenario, env)
    chain.append("run_completed", {
        "attack_succeeded": outcome.attack_succeeded, "task_completed": outcome.task_completed,
        "observed_effects": list(outcome.observed_effects),
    })
    return RunResult(run_id, mode, tuple(records), outcome, tuple(chain.events), chain.head)


def run_pair(scenario: Scenario) -> PairResult:
    intents = agent.plan(scenario)
    pair_id = str(uuid.uuid4())
    return PairResult(
        pair_id=pair_id,
        scenario=scenario,
        intents=intents,
        baseline=run_once(scenario, intents, RunMode.BASELINE, pair_id),
        protected=run_once(scenario, intents, RunMode.PROTECTED, pair_id),
    )
