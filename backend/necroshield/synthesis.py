"""Blue Team: structured policy candidates.

Every candidate is an ordinary immutable Policy made of Grants, so it passes the same validation as
a hand-written one and is enforced by the same gateway. Nothing here modifies a scenario's default
policy, the enforcement engine, or stored data: a candidate is just data until a human runs it.

Inputs a strategy may use:
  - the TRUSTED TRACE: the calls of the scenario's trusted plan, executed alone in a clean
    environment, with injected instructions ignored (the task specification, not attacker input);
  - for `violation_patch` only, the VIOLATING CALLS: calls an unprotected run made that are not in
    the trusted trace (the "observed policy violations").
Strategies never see attacker-chosen values except through those violating calls.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Iterable

from . import agent
from .contracts import RunMode, ToolCall
from .evidence import is_redactable
from .gateway import Gateway
from .runner import run_once
from .scenarios import Grant, Policy, Scenario
from .tools import TOOLS, Environment

# Arguments that name a resource or a destination: pinning them is what makes a grant meaningful.
RESOURCE_ARGS = frozenset({"path", "customer_id", "key", "to", "attach", "report_id"})

_digest_cache: dict[str, tuple[ToolCall, ...]] = {}
_intent_cache: dict[str, tuple[ToolCall, ...]] = {}


def trusted_trace(scenario: Scenario) -> tuple[ToolCall, ...]:
    """Bound calls of the trusted plan, run alone. Cached per scenario digest (definitions are immutable)."""
    key = scenario.digest()
    if key not in _digest_cache:
        gateway = Gateway(Environment.from_scenario(scenario), policy=None)
        facts: dict[str, str] = {}
        trace = []
        for intent in scenario.plan:
            call = agent.bind(intent, facts)
            trace.append(call)
            record = gateway.execute(call)
            if record.output:
                agent.learn(facts, call, record.output)
        _digest_cache[key] = tuple(trace)
    return _digest_cache[key]


def intended_calls(scenario: Scenario) -> tuple[ToolCall, ...]:
    key = scenario.digest()
    if key not in _intent_cache:
        _intent_cache[key] = agent.plan(scenario)
    return _intent_cache[key]


def call_key(call: ToolCall) -> tuple[str, tuple[tuple[str, str], ...]]:
    return call.tool, tuple(sorted(call.args.items()))


def plan_keys(scenario: Scenario) -> frozenset:
    """Keys of the trusted plan's call TEMPLATES. Intents are templates until bound, so an intent is
    legitimate exactly when its template is in the plan. Matching on bound values would misfile a
    legitimate call whose placeholders resolved differently after a denial or a poisoned read."""
    return frozenset(call_key(c) for c in scenario.plan)


def violating_calls(scenario: Scenario) -> tuple[ToolCall, ...]:
    """Bound calls an unprotected run dispatched for intents that are not in the trusted plan."""
    legit = plan_keys(scenario)
    intents = intended_calls(scenario)
    baseline = run_once(scenario, intents, RunMode.BASELINE)
    return tuple(r.call for intent, r in zip(intents, baseline.records) if call_key(intent) not in legit)


def complexity(policy: Policy) -> int:
    """Grants plus pinned argument values: a rough measure of how much a reviewer must read."""
    return len(policy.grants) + sum(len(v) for g in policy.grants for v in g.allowed_args.values() if v is not None)


def _build(trace: Iterable[ToolCall], pinned: Callable[[str, str], bool], prefix: str) -> tuple[Grant, ...]:
    """One grant per distinct (tool, argument names) shape in the trace. Pinned arguments are
    restricted to the values seen in that shape; the rest accept any bounded string."""
    groups: dict[tuple[str, tuple[str, ...]], list[ToolCall]] = defaultdict(list)
    for call in trace:
        groups[(call.tool, tuple(sorted(call.args)))].append(call)
    grants = []
    for index, ((tool, names), calls) in enumerate(sorted(groups.items())):
        allowed: dict[str, tuple[str, ...] | None] = {}
        for name in names:
            values = tuple(sorted({c.args[name] for c in calls}))
            can_pin = pinned(tool, name) and not any(is_redactable(v) for v in values)
            allowed[name] = values if can_pin else None
        grants.append(Grant(f"g-{prefix}-{index}-{tool}"[:64], tool, allowed))
    return tuple(grants)


def _policy(name: str, grants: tuple[Grant, ...]) -> Policy:
    return Policy(f"{name}/1.0.0", grants)


# --- per-scenario strategies -------------------------------------------------------------------

def allow_all(_scenario: Scenario) -> Policy:
    grants = tuple(Grant(f"g-any-{s.name}"[:64], s.name, {a: None for a in s.required + s.optional})
                   for s in TOOLS.values())
    return _policy("allow-all", grants)


def deny_all(_scenario: Scenario) -> Policy:
    return _policy("deny-all", ())


def tool_allowlist(scenario: Scenario) -> Policy:
    return _policy("tool-allowlist", _build(trusted_trace(scenario), lambda t, n: False, "t"))


def scoped_trace(scenario: Scenario) -> Policy:
    return _policy("scoped-trace", _build(trusted_trace(scenario), lambda t, n: n in RESOURCE_ARGS, "s"))


def exact_trace(scenario: Scenario) -> Policy:
    return _policy("exact-trace", _build(trusted_trace(scenario), lambda t, n: True, "e"))


def violation_patch(scenario: Scenario) -> Policy:
    """Start from the tool allow-list, then pin only the arguments on which an observed
    violating call deviates from every trusted call to the same tool."""
    trace = trusted_trace(scenario)
    pin: set[tuple[str, str]] = set()
    for bad in violating_calls(scenario):
        for name, value in bad.args.items():
            seen = {c.args[name] for c in trace if c.tool == bad.tool and name in c.args}
            if seen and value not in seen:
                pin.add((bad.tool, name))
    return _policy("violation-patch", _build(trace, lambda t, n: (t, n) in pin, "v"))


# --- global strategies (one policy for many tasks, fitted on a scenario set) -------------------

def fit_global_allowlist(fit: Iterable[Scenario]) -> Callable[[Scenario], Policy]:
    policy = _policy("global-tool-allowlist",
                     _build([c for s in fit for c in trusted_trace(s)], lambda t, n: False, "gt"))
    return lambda _scenario: policy


def fit_global_scoped(fit: Iterable[Scenario]) -> Callable[[Scenario], Policy]:
    policy = _policy("global-scoped",
                     _build([c for s in fit for c in trusted_trace(s)], lambda t, n: n in RESOURCE_ARGS, "gs"))
    return lambda _scenario: policy


@dataclass(frozen=True)
class Strategy:
    name: str
    scope: str            # "per-scenario" or "global"
    inputs: str           # what the strategy is allowed to see
    description: str
    make: Callable[[Iterable[Scenario]], Callable[[Scenario], Policy]]


def _per_scenario(fn: Callable[[Scenario], Policy]) -> Callable[[Iterable[Scenario]], Callable[[Scenario], Policy]]:
    return lambda _fit: fn


STRATEGIES: tuple[Strategy, ...] = (
    Strategy("allow_all", "per-scenario", "nothing", "One unconstrained grant per tool. Equivalent to no protection.",
             _per_scenario(allow_all)),
    Strategy("deny_all", "per-scenario", "nothing", "No grants. Blocks every call, including the legitimate task.",
             _per_scenario(deny_all)),
    Strategy("tool_allowlist", "per-scenario", "trusted plan", "Allow only the tools the trusted plan uses, with any arguments.",
             _per_scenario(tool_allowlist)),
    Strategy("violation_patch", "per-scenario", "trusted plan + observed violations",
             "Tool allow-list, then pin only the arguments on which an observed violating call deviates.",
             _per_scenario(violation_patch)),
    Strategy("scoped_trace", "per-scenario", "trusted plan",
             "Pin every resource and destination argument to the values the trusted plan uses; free text stays open.",
             _per_scenario(scoped_trace)),
    Strategy("exact_trace", "per-scenario", "trusted plan",
             "Pin every argument, including free text, to the trusted plan's values.", _per_scenario(exact_trace)),
    Strategy("global_tool_allowlist", "global", "development traces only",
             "One policy for all tasks: tools used by any development task, any arguments.", fit_global_allowlist),
    Strategy("global_scoped", "global", "development traces only",
             "One policy for all tasks: resource and destination values used by any development task.", fit_global_scoped),
)
STRATEGY_BY_NAME = {s.name: s for s in STRATEGIES}
