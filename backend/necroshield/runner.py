"""Paired baseline/protected execution of one scenario's intended calls."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass
from typing import Any

from . import agent
from .contracts import REPLAY_MODE, Decision, DispatchRecord, Outcome, RunMode, ToolCall
from .evaluator import evaluate_outcome
from .evidence import EXPORT_FORMAT, EventChain
from .policy import evaluate
from .scenarios import Scenario
from .tools import Environment, ToolError, invoke

_UNCHECKED = Decision(True, "baseline: no policy enforcement")


@dataclass(frozen=True)
class RunResult:
    run_id: str
    mode: RunMode
    records: tuple[DispatchRecord, ...]
    outcome: Outcome
    events: tuple[dict[str, Any], ...]
    head: str


@dataclass(frozen=True)
class PairResult:
    pair_id: str
    scenario: Scenario
    intents: tuple[ToolCall, ...]
    baseline: RunResult
    protected: RunResult

    def export(self) -> dict[str, Any]:
        s = self.scenario
        return {
            "format": EXPORT_FORMAT,
            "pair_id": self.pair_id,
            "replay_mode": REPLAY_MODE,
            "scenario": {"id": s.scenario_id, "version": s.version, "kind": s.kind, "digest": s.digest()},
            "policy_version": s.policy.version,
            "intents": [c.to_dict() for c in self.intents],
            "runs": [_export_run(r) for r in (self.baseline, self.protected)],
        }


def _export_run(run: RunResult) -> dict[str, Any]:
    return {
        "run_id": run.run_id,
        "mode": run.mode.value,
        "outcome": asdict(run.outcome) | {"observed_effects": list(run.outcome.observed_effects)},
        "head": run.head,
        "events": list(run.events),
    }


def _dispatch(env: Environment, call: ToolCall, decision: Decision) -> DispatchRecord:
    if not decision.allowed:
        return DispatchRecord(call, decision, dispatched=False)
    try:
        return DispatchRecord(call, decision, dispatched=True, output=invoke(env, call.tool, call.args))
    except ToolError as exc:
        return DispatchRecord(call, decision, dispatched=True, error=str(exc))


def run_once(scenario: Scenario, intents: tuple[ToolCall, ...], mode: RunMode) -> RunResult:
    run_id = str(uuid.uuid4())
    env = Environment.from_scenario(scenario)
    chain = EventChain(run_id)
    chain.append("run_started", {
        "mode": mode.value, "replay_mode": REPLAY_MODE, "scenario_id": scenario.scenario_id,
        "scenario_version": scenario.version, "scenario_digest": scenario.digest(),
        "policy_version": scenario.policy.version,
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
    return PairResult(
        pair_id=str(uuid.uuid4()),
        scenario=scenario,
        intents=intents,
        baseline=run_once(scenario, intents, RunMode.BASELINE),
        protected=run_once(scenario, intents, RunMode.PROTECTED),
    )
