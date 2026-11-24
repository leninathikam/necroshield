"""Paired baseline/protected execution of one scenario's intended calls, plus counterfactual
attribution of which protected denials changed the observable outcome."""

from __future__ import annotations

import copy
import hashlib
import time
import uuid
from dataclasses import dataclass
from typing import Any

from . import agent
from .contracts import REPLAY_MODE, Decision, DispatchRecord, Outcome, RunMode, ToolCall, canonical_json
from .evaluator import evaluate_outcome
from .evidence import EXPORT_FORMAT, EventChain, redact
from .gateway import Gateway
from .scenarios import Policy, Scenario
from .tools import Environment


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
    duration_ms: float

    def export(self) -> dict[str, Any]:
        # The exported outcome is the chained run_completed data, so it is redacted and hash-bound.
        return {"run_id": self.run_id, "mode": self.mode.value, "outcome": self.events[-1]["data"],
                "head": self.head, "events": list(self.events)}


@dataclass(frozen=True)
class PairResult:
    pair_id: str
    scenario: Scenario
    policy: Policy
    intents: tuple[ToolCall, ...]
    baseline: RunResult
    protected: RunResult

    @property
    def policy_source(self) -> str:
        return "scenario_default" if self.policy.digest() == self.scenario.policy.digest() else "custom"

    def export(self) -> dict[str, Any]:
        s = self.scenario
        return copy.deepcopy({
            "format": EXPORT_FORMAT,
            "pair_id": self.pair_id,
            "replay_mode": REPLAY_MODE,
            "scenario": redact({
                "id": s.scenario_id, "version": s.version, "kind": s.kind, "digest": s.digest(),
                "attack_checks": [c.to_dict() for c in s.attack_checks],
                "task_checks": [c.to_dict() for c in s.task_checks],
            }),
            "policy": {"digest": self.policy.digest(), "source": self.policy_source, **self.policy.to_dict()},
            "intents": redacted_intents(self.intents),
            "runs": [self.baseline.export(), self.protected.export()],
        })


def _execute(scenario: Scenario, intents: tuple[ToolCall, ...], policy: Policy | None,
             force_allow: frozenset[int] = frozenset()) -> tuple[list[DispatchRecord], Environment]:
    env = Environment.from_scenario(scenario)
    gateway = Gateway(env, policy)
    facts: dict[str, str] = {}
    records = []
    for index, intent in enumerate(intents):
        call = agent.bind(intent, facts)  # placeholders bound from this run's own observations
        decision = gateway.decide(call)
        if index in force_allow and not decision.allowed:
            decision = Decision(True, "counterfactual: denial lifted for attribution")
        record = gateway.execute(call, decision)
        if record.output:
            agent.learn(facts, call, record.output)
        records.append(record)
    return records, env


def run_once(scenario: Scenario, intents: tuple[ToolCall, ...], mode: RunMode, pair_id: str = "",
             policy: Policy | None = None) -> RunResult:
    policy = policy or scenario.policy
    run_id = str(uuid.uuid4())
    started = time.perf_counter()
    chain = EventChain(run_id)
    chain.append("run_started", {
        "pair_id": pair_id, "mode": mode.value, "replay_mode": REPLAY_MODE,
        "scenario_id": scenario.scenario_id, "scenario_version": scenario.version,
        "scenario_digest": scenario.digest(), "policy_digest": policy.digest(),
        "intents_digest": intents_digest(intents),
    })
    records, env = _execute(scenario, intents, policy if mode is RunMode.PROTECTED else None)
    for index, (intent, record) in enumerate(zip(intents, records)):
        chain.append("tool_call", {
            "intent_index": index, **intent.to_dict(), "bound_args": dict(record.call.args),
            "allowed": record.decision.allowed,
            "reason": record.decision.reason, "grant_id": record.decision.grant_id,
            "dispatched": record.dispatched, "output": record.output, "error": record.error,
        })
    outcome = evaluate_outcome(scenario, env)
    chain.append("run_completed", {
        "attack_succeeded": outcome.attack_succeeded, "task_completed": outcome.task_completed,
        "observed_effects": list(outcome.observed_effects),
    })
    duration = (time.perf_counter() - started) * 1000
    return RunResult(run_id, mode, tuple(records), outcome, tuple(chain.events), chain.head, duration)


def run_pair(scenario: Scenario, policy: Policy | None = None) -> PairResult:
    policy = policy or scenario.policy
    intents = agent.plan(scenario)
    pair_id = str(uuid.uuid4())
    return PairResult(
        pair_id=pair_id, scenario=scenario, policy=policy, intents=intents,
        baseline=run_once(scenario, intents, RunMode.BASELINE, pair_id, policy),
        protected=run_once(scenario, intents, RunMode.PROTECTED, pair_id, policy),
    )


def decisive_denials(pair: PairResult) -> list[dict[str, Any]]:
    """For each protected denial, re-run with only that denial lifted and report whether the
    observable outcome changes. This is an exact counterfactual over the deterministic fixture,
    not a statistical estimate. Results are derived analysis, not part of the evidence chain."""
    base = pair.protected.outcome
    findings = []
    for index, record in enumerate(pair.protected.records):
        if record.decision.allowed:
            continue
        _, env = _execute(pair.scenario, pair.intents, pair.policy, frozenset({index}))
        lifted = evaluate_outcome(pair.scenario, env)
        findings.append({
            "intent_index": index, "tool": record.call.tool, "reason": record.decision.reason,
            "attack_if_allowed": lifted.attack_succeeded, "task_if_allowed": lifted.task_completed,
            "decisive": lifted.attack_succeeded != base.attack_succeeded or lifted.task_completed != base.task_completed,
        })
    return redact(findings)
