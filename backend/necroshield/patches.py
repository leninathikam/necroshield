"""Security patch compiler: an observed failure becomes a structured policy patch.

A patch is DATA. It names the base policy under which an attack succeeded, the proposed replacement,
the grant-level operations between them, a regression-test specification, and the results of running
that specification. Nothing here edits a scenario default or the enforcement engine, and nothing is
applied: the patch is marked `proposed`, and applying it means a human runs the proposed policy
(`/api/theatre/{id}/approve`), which records it as a custom policy.

A patch can be re-checked from its own contents (`check_patch`), without trusting the server that
produced it: it embeds both policies, the scenario digest, and every case's expectation.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .contracts import canonical_json
from .corpus import CORPUS, DEVELOPMENT_IDS
from .optimizer import ScenarioEval, evaluate_scenario, score
from .runner import run_pair
from .scenarios import Policy, Scenario
from .synthesis import STRATEGY_BY_NAME, call_key, intended_calls, plan_keys
from .variants import variant, variants

PATCH_FORMAT = "necroshield.patch/1"
BASES = ("allow_all", "tool_allowlist", "violation_patch")
TARGETS = ("scoped_trace", "exact_trace", "violation_patch")
VARIANT_SEEDS = 3


def _policy(strategy: str, scenario: Scenario) -> Policy:
    return STRATEGY_BY_NAME[strategy].make([scenario])(scenario)


def _shape(grant: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
    return grant["tool"], tuple(sorted(grant["allowed_args"]))


def _describe(allowed: dict[str, Any]) -> str:
    return "; ".join(f"{k} {'any value' if v is None else 'only ' + ' | '.join(v)}" for k, v in sorted(allowed.items()))


def operations(base: Policy, proposed: Policy) -> list[dict[str, Any]]:
    """Grant-level difference. Grants are matched by (tool, argument names), not by id."""
    before = {_shape(g.to_dict()): g.to_dict() for g in base.grants}
    after = {_shape(g.to_dict()): g.to_dict() for g in proposed.grants}
    ops: list[dict[str, Any]] = []
    for key in sorted(set(before) | set(after)):
        b, a = before.get(key), after.get(key)
        tool = key[0]
        if b and not a:
            ops.append({"op": "remove_grant", "tool": tool, "grant": b,
                        "explain": f"{tool} is no longer allowed with arguments {', '.join(key[1]) or 'none'}."})
        elif a and not b:
            ops.append({"op": "add_grant", "tool": tool, "grant": a, "explain": f"{tool} becomes allowed: {_describe(a['allowed_args'])}."})
        elif a != b and a and b:
            changed = [k for k in a["allowed_args"] if a["allowed_args"][k] != b["allowed_args"][k]]
            ops.append({"op": "replace_grant", "tool": tool, "from": b, "to": a,
                        "explain": f"{tool}: " + "; ".join(
                            f"{k} {_describe({k: b['allowed_args'][k]}).split(' ', 1)[1]} -> {_describe({k: a['allowed_args'][k]}).split(' ', 1)[1]}"
                            for k in changed) + "."})
    return ops


def _case(case_id: str, scenario: Scenario, policy: str, expect: dict[str, Any], split: str, **extra: Any) -> dict[str, Any]:
    return {"id": case_id, "scenario_id": scenario.scenario_id, "scenario_digest": scenario.digest(), "policy": policy,
            "split": split, "expect": expect, **extra}


def _split(scenario_id: str) -> str:
    return "development" if scenario_id in DEVELOPMENT_IDS else "held_out"


def regression_spec(failing: Scenario, count: int = VARIANT_SEEDS) -> list[dict[str, Any]]:
    """Cases that must hold for the proposed policy: the failure is fixed, variants stay fixed, sibling
    attacks on the same task are stopped, and every benign control on the same task still completes."""
    key = plan_keys(failing)
    split = _split(failing.scenario_id)
    fixed = {"attack_succeeded": False, "task_completed": True, "legit_denied": 0}
    cases = [_case("failure-reproduces-on-base", failing, "base", {"attack_succeeded": True}, split),
             _case("fixed-on-proposed", failing, "proposed", fixed, split)]
    for v in variants(failing, count):
        seed = int(v.scenario_id.rsplit("_v", 1)[1])
        cases.append(_case(f"variant-{seed}", v, "proposed", fixed, split, variant_of=failing.scenario_id, seed=seed))
    for other in CORPUS.values():
        if other.scenario_id == failing.scenario_id or plan_keys(other) != key:
            continue
        if other.kind == "attack":
            cases.append(_case(f"sibling-{other.scenario_id}", other, "proposed",
                               {"attack_succeeded": False, "task_completed": True}, _split(other.scenario_id)))
        else:
            cases.append(_case(f"control-{other.scenario_id}", other, "proposed",
                               {"attack_succeeded": False, "task_completed": True, "legit_denied": 0}, _split(other.scenario_id)))
    return cases


def _resolve(case: dict[str, Any]) -> Scenario:
    if "variant_of" in case:
        return variant(CORPUS[case["variant_of"]], case["seed"])
    return CORPUS[case["scenario_id"]]


def run_case(case: dict[str, Any], base: Policy, proposed: Policy) -> dict[str, Any]:
    scenario = _resolve(case)
    problems = [] if scenario.digest() == case["scenario_digest"] else ["scenario definition differs from the one the patch was built for"]
    result: ScenarioEval = evaluate_scenario(scenario, base if case["policy"] == "base" else proposed)
    observed = {"attack_succeeded": result.attack_succeeded, "task_completed": result.task_completed, "legit_denied": result.legit_denied}
    problems += [f"{k}: expected {want}, observed {observed[k]}" for k, want in case["expect"].items() if observed[k] != want]
    return {"id": case["id"], "split": case["split"], "passed": not problems, "problems": problems, "observed": observed}


def _aggregate(failing: Scenario, base: Policy, proposed: Policy) -> dict[str, Any]:
    """Whole development and held-out sets, before and after. Only scenarios that share the failing
    task use the base/proposed policy; every other scenario keeps its default, so a patch scoped to one
    task cannot hide a regression elsewhere or claim credit for it."""
    key, out = plan_keys(failing), {}
    for label, ids in (("development", DEVELOPMENT_IDS), ("held_out", set(CORPUS) - DEVELOPMENT_IDS)):
        members = [CORPUS[i] for i in sorted(ids)]
        def pick(s: Scenario, special: Policy) -> Policy:
            return special if plan_keys(s) == key else s.policy
        out[label] = {"before": score(evaluate_scenario(s, pick(s, base)) for s in members),
                      "after": score(evaluate_scenario(s, pick(s, proposed)) for s in members),
                      "scenarios_using_patch": sum(plan_keys(s) == key for s in members)}
    return out


def compile_patch(scenario_id: str, base: str = "tool_allowlist", target: str = "scoped_trace",
                  base_from: str | None = None) -> dict[str, Any]:
    scenario = CORPUS.get(scenario_id)
    if scenario is None or scenario.kind != "attack":
        raise KeyError(scenario_id)
    if base not in BASES or target not in TARGETS:
        raise KeyError((base, target))
    donor = CORPUS.get(base_from) if base_from else scenario
    if donor is None or (base_from and plan_keys(donor) != plan_keys(scenario)):
        raise KeyError(base_from)  # a deployed policy can only be reused on a scenario with the same trusted task
    base_policy, proposed = _policy(base, donor), _policy(target, scenario)
    failure = run_pair(scenario, base_policy)
    if not failure.protected.outcome.attack_succeeded:
        raise ValueError(f"no failure observed: the attack is already stopped under '{base}'")
    intents = intended_calls(scenario)
    legit = {call_key(c) for c in scenario.plan}
    let_through = [{"tool": r.call.tool, "args": dict(r.call.args)} for i, r in zip(intents, failure.protected.records)
                   if call_key(i) not in legit and r.decision.allowed]
    ops = operations(base_policy, proposed)
    spec = regression_spec(scenario)
    results = [run_case(c, base_policy, proposed) for c in spec]
    core = {
        "format": PATCH_FORMAT,
        "scenario": {"id": scenario.scenario_id, "version": scenario.version, "digest": scenario.digest(), "split": _split(scenario_id)},
        "failure": {"base_strategy": base, "base_from": donor.scenario_id, "base_policy": {**base_policy.to_dict(), "digest": base_policy.digest()},
                    "observed_effects": list(failure.protected.outcome.observed_effects), "calls_let_through": let_through},
        "proposed": {"strategy": target, "policy": {**proposed.to_dict(), "digest": proposed.digest()}},
        "operations": ops,
        "regression_spec": spec,
    }
    explanation = [
        f"Under policy '{base_policy.version}', the attack in '{scenario.title}' succeeded: "
        + "; ".join(core["failure"]["observed_effects"] and [e for e in core["failure"]["observed_effects"] if e.startswith("attack")]) + ".",
        "The base policy let these attacker-driven calls through: "
        + ", ".join(f"{c['tool']}({', '.join(f'{k}={v}' for k, v in c['args'].items())})" for c in let_through) + ".",
        *[op["explain"] for op in ops],
        "Nothing is applied. A person must approve the proposed policy; running it records it as a custom policy.",
    ]
    patch = {**core, "results": results, "all_cases_pass": all(r["passed"] for r in results),
             "aggregate": _aggregate(scenario, base_policy, proposed),
             "activation": {"status": "proposed", "applied": False, "requires": "human approval"},
             "explanation": explanation, "evaluation_mode": "deterministic_intent_replay"}
    patch["patch_id"] = hashlib.sha256(canonical_json(core).encode()).hexdigest()[:16]
    patch["report_markdown"] = to_markdown(patch)
    return patch


def to_markdown(patch: dict[str, Any]) -> str:
    s = patch["scenario"]
    lines = [f"# Security patch {patch['patch_id']}", "", f"Scenario: `{s['id']}` v{s['version']} ({s['split']}), digest `{s['digest'][:16]}…`", "",
             "## What failed", *[f"- {e}" for e in patch["failure"]["observed_effects"]], "", "## Proposed change", *[f"- {line}" for line in patch["explanation"]],
             "", "## Regression results", "| case | split | result |", "|---|---|---|",
             *[f"| {r['id']} | {r['split']} | {'pass' if r['passed'] else 'FAIL: ' + '; '.join(r['problems'])} |" for r in patch["results"]],
             "", "Status: **proposed**. Requires human approval; nothing has been applied."]
    return "\n".join(lines) + "\n"


def _strip_timing(value: Any) -> Any:
    """Wall-clock fields are measurements, not claims; drop them before comparing."""
    if isinstance(value, dict):
        return {k: _strip_timing(v) for k, v in value.items() if k != "median_ms"}
    return [_strip_timing(v) for v in value] if isinstance(value, list) else value


def check_patch(patch: Any) -> list[str]:
    """Re-check a patch from its own contents. Returns problems; empty means every claim reproduced."""
    problems: list[str] = []
    try:
        if not isinstance(patch, dict) or patch.get("format") != PATCH_FORMAT:
            return ["not a necroshield.patch/1 document"]
        scenario = CORPUS[patch["scenario"]["id"]]
        if scenario.digest() != patch["scenario"]["digest"]:
            problems.append("scenario digest differs from this repository's definition")
        base = Policy.from_dict({k: v for k, v in patch["failure"]["base_policy"].items() if k != "digest"})
        proposed = Policy.from_dict({k: v for k, v in patch["proposed"]["policy"].items() if k != "digest"})
        if base.digest() != patch["failure"]["base_policy"]["digest"] or proposed.digest() != patch["proposed"]["policy"]["digest"]:
            problems.append("embedded policy digest does not match its policy")
        if operations(base, proposed) != patch["operations"]:
            problems.append("operations do not follow from the base and proposed policies")
        core = {k: patch[k] for k in ("format", "scenario", "failure", "proposed", "operations", "regression_spec")}
        if hashlib.sha256(canonical_json(core).encode()).hexdigest()[:16] != patch["patch_id"]:
            problems.append("patch id does not match the patch contents")
        if patch.get("activation") != {"status": "proposed", "applied": False, "requires": "human approval"}:
            problems.append("activation must be proposed, unapplied, and require human approval")
        for case in patch["regression_spec"]:
            outcome = run_case(case, base, proposed)
            problems += [f"{case['id']}: {p}" for p in outcome["problems"]]
        if [r["id"] for r in patch["results"]] != [c["id"] for c in patch["regression_spec"]]:
            problems.append("recorded results do not cover the regression spec")
        # A patch is the compiler's deterministic output. Recompile from its stated inputs and compare
        # everything, so a trimmed spec, a swapped policy, or edited results cannot pass on self-consistency.
        try:
            recompiled = compile_patch(patch["scenario"]["id"], patch["failure"]["base_strategy"], patch["proposed"]["strategy"],
                                       patch["failure"]["base_from"] if patch["failure"]["base_from"] != patch["scenario"]["id"] else None)
        except (KeyError, ValueError) as exc:
            problems.append(f"cannot recompile this patch from its stated inputs: {exc}")
        else:
            for key in sorted(set(recompiled) | set(patch)):
                if _strip_timing(recompiled.get(key)) != _strip_timing(patch.get(key)):
                    problems.append(f"'{key}' differs from the recompiled patch")
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        problems.append(f"malformed patch: {type(exc).__name__}: {exc}")
    return problems
