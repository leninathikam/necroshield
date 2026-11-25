"""Red Team variants, corpus, Blue Team synthesis, and the independent evaluator."""

import ast
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from necroshield import corpus, synthesis, variants as red
from necroshield.catalog import REGISTRY
from necroshield.contracts import RunMode
from necroshield.optimizer import (candidate_policy, dominates, evolve, feasibility, pareto_front, theatre,
                                   evaluate_scenario)
from necroshield.runner import run_pair
from necroshield.scenarios import Policy

BACKEND = Path(__file__).resolve().parents[1]
CORPUS = corpus.CORPUS
ATTACKS = [s for s in CORPUS.values() if s.kind == "attack"]
CONTROLS = [s for s in CORPUS.values() if s.kind == "control"]


# --- corpus ------------------------------------------------------------------------------------

def test_corpus_shape_and_split_are_fixed():
    assert (len(CORPUS), len(ATTACKS), len(CONTROLS)) == (21, 10, 11)
    assert len({s.attack_class for s in ATTACKS}) == 6  # added attacks are new contexts, not new classes
    assert corpus.DEVELOPMENT_IDS | corpus.HELD_OUT_IDS == set(CORPUS)
    assert not corpus.DEVELOPMENT_IDS & corpus.HELD_OUT_IDS
    # Pinned: the split must not drift to flatter any result.
    assert sorted(corpus.DEVELOPMENT_IDS) == [
        "benign_invoice", "benign_memory_note", "benign_notify_billing", "benign_report_only", "benign_second_customer",
        "data_exfiltration", "document_injection", "memory_poisoning", "memory_poisoning_context", "scope_manipulation"]
    assert all(any(s.kind == k for s in corpus.held_out()) for k in ("attack", "control"))


def test_catalog_scenarios_are_untouched_by_the_corpus():
    assert all(CORPUS[sid] is REGISTRY[sid] for sid in REGISTRY)


@pytest.mark.parametrize("scenario", list(CORPUS.values()), ids=lambda s: s.scenario_id)
def test_every_corpus_scenario_behaves_as_designed(scenario, verifier):
    pair = run_pair(scenario)
    b, q = pair.baseline.outcome, pair.protected.outcome
    if scenario.kind == "attack":
        assert b.attack_succeeded and not q.attack_succeeded and q.task_completed
    else:
        assert not b.attack_succeeded and b.task_completed and q.task_completed
        assert all(r.decision.allowed for r in pair.protected.records)
    assert verifier.verify(pair.export()) == []


# --- Red Team ----------------------------------------------------------------------------------

def test_variants_are_reproducible_across_processes_with_different_hash_seeds():
    code = ("from necroshield.corpus import CORPUS; from necroshield.variants import variants;"
            "print([v.digest() for s in CORPUS.values() for v in variants(s, 3)])")
    outs = {subprocess.run([sys.executable, "-c", code], cwd=BACKEND, capture_output=True, text=True,
                           env={**os.environ, "PYTHONHASHSEED": seed}).stdout for seed in ("1", "2", "77")}
    assert len(outs) == 1 and next(iter(outs)).startswith("[")


@pytest.mark.parametrize("scenario", ATTACKS, ids=lambda s: s.scenario_id)
def test_variants_stay_attacks_and_change_only_values(scenario):
    for v in red.variants(scenario, 3):
        assert v.scenario_id.startswith(scenario.scenario_id + "_v")
        assert v.attack_class == scenario.attack_class and v.kind == "attack"
        assert [c.tool for c in v.plan] == [c.tool for c in scenario.plan]
        assert v.digest() != scenario.digest()
        pair = run_pair(v)
        assert pair.baseline.outcome.attack_succeeded and not pair.protected.outcome.attack_succeeded


def test_variants_are_bounded_unique_and_controls_have_none():
    base = CORPUS["document_injection"]
    assert len(red.variants(base, 99)) <= red.MAX_VARIANTS
    keys = {red._content_key(v) for v in red.variants(base, 4)}
    assert len(keys) == len(red.variants(base, 4))
    assert red.variants(CORPUS["benign_invoice"], 3) == ()


# --- Blue Team ---------------------------------------------------------------------------------

def test_trusted_trace_ignores_injected_instructions():
    trace = synthesis.trusted_trace(CORPUS["tool_response_injection"])
    assert all("collector@sink.invalid" not in c.args.get("to", "") for c in trace)
    clean = replace(CORPUS["tool_response_injection"], customer_records={
        k: v.split("\nnote:")[0] for k, v in CORPUS["tool_response_injection"].customer_records.items()})
    assert [c.to_dict() for c in synthesis.trusted_trace(clean)] == [
        c.to_dict() for c in synthesis.trusted_trace(CORPUS["tool_response_injection"])]


def test_trace_equals_the_benign_runs_bound_calls():
    for s in CONTROLS:
        bound = [r.call.to_dict() for r in run_pair(s).baseline.records]
        assert [c.to_dict() for c in synthesis.trusted_trace(s)] == bound


def test_legitimate_calls_are_identified_by_template_not_by_bound_values():
    s = CORPUS["memory_poisoning"]
    violating = synthesis.violating_calls(s)
    assert [c.tool for c in violating] == ["write_memory"]  # the poisoned report is a consequence, not an attack call
    denied = evaluate_scenario(s, synthesis.deny_all(s))
    assert denied.legit_denied == denied.legit_calls == len(s.plan)


@pytest.mark.parametrize("scenario", list(CORPUS.values()), ids=lambda s: s.scenario_id)
def test_scoped_trace_matches_the_manual_outcome_on_every_scenario(scenario):
    result = evaluate_scenario(scenario, synthesis.scoped_trace(scenario))
    assert not result.attack_succeeded and result.task_completed and result.legit_denied == 0


def test_allow_all_equals_no_protection_and_deny_all_blocks_the_task():
    s = CORPUS["document_injection"]
    unprotected, allow, deny = evaluate_scenario(s, None), evaluate_scenario(s, synthesis.allow_all(s)), evaluate_scenario(s, synthesis.deny_all(s))
    assert (allow.attack_succeeded, allow.task_completed) == (unprotected.attack_succeeded, unprotected.task_completed)
    assert not deny.task_completed and deny.legit_denied == deny.legit_calls


def test_violation_patch_pins_only_the_deviating_argument():
    policy = synthesis.violation_patch(CORPUS["tool_response_injection"])
    send = next(g for g in policy.grants if g.tool == "send_message")
    assert send.allowed_args["to"] == ("billing@finance.invalid",)
    assert send.allowed_args["attach"] is None and send.allowed_args["body"] is None


def test_exact_trace_pins_free_text_and_scoped_trace_does_not():
    s = CORPUS["benign_report_only"]
    exact = next(g for g in synthesis.exact_trace(s).grants if g.tool == "write_report")
    scoped = next(g for g in synthesis.scoped_trace(s).grants if g.tool == "write_report")
    assert exact.allowed_args["body"] == ("Invoice INV-2026-0413 total 124.00 USD",) and scoped.allowed_args["body"] is None


def test_global_strategies_are_fitted_on_development_only():
    policy = synthesis.STRATEGY_BY_NAME["global_scoped"].make(corpus.development())(CORPUS["document_injection"])
    text = json.dumps(policy.to_dict())
    for held_out_only in ("auditor@finance.invalid", '"audit"', "customer_review"):
        assert held_out_only not in text


def test_every_synthesised_policy_is_an_ordinary_validated_policy():
    for s in CORPUS.values():
        for strategy in synthesis.STRATEGIES:
            policy = strategy.make(corpus.development())(s)
            assert isinstance(policy, Policy) and Policy.from_dict(policy.to_dict()) == policy


def test_synthesis_and_evaluation_never_touch_enforcement_or_defaults():
    before = {sid: (s.digest(), s.policy.digest()) for sid, s in CORPUS.items()}
    evolve(3)
    theatre("document_injection")
    assert before == {sid: (s.digest(), s.policy.digest()) for sid, s in CORPUS.items()}
    package = BACKEND / "necroshield"
    for module in ("synthesis.py", "optimizer.py", "variants.py", "corpus.py"):
        imported = {n.module for n in ast.walk(ast.parse((package / module).read_text())) if isinstance(n, ast.ImportFrom)}
        assert "policy" not in {i.split(".")[-1] for i in imported if i}, module  # none of them re-implements enforcement


# --- evaluator ---------------------------------------------------------------------------------

def test_pareto_dominance():
    assert dominates((0, 0, 0), (1, 0, 0)) and not dominates((0, 0, 0), (0, 0, 0)) and not dominates((1, 0), (0, 1))
    assert pareto_front({"a": (0, 1), "b": (1, 0), "c": (1, 1), "d": (0, 1)}) == {"a", "b", "d"}


def test_mandatory_constraint_rejects_leaks():
    leaked = evaluate_scenario(CORPUS["document_injection"], None)
    ok, reason = feasibility([leaked])
    assert not ok and "forbidden effect" in reason


def test_evolution_results_are_pinned():
    r = evolve(3)
    cell = lambda s, split, key: (s[split][key]["numerator"], s[split][key]["denominator"])  # noqa: E731
    rows = {s["name"]: s for s in r["strategies"]}
    assert r["corpus"]["development"] == {"scenarios": 10, "attacks": 5, "controls": 5}
    assert r["corpus"]["held_out"] == {"scenarios": 11, "attacks": 5, "controls": 6}
    assert {n: row["feasible"] for n, row in rows.items()} == {
        "allow_all": False, "deny_all": True, "tool_allowlist": False, "violation_patch": True, "scoped_trace": True,
        "exact_trace": True, "global_tool_allowlist": False, "global_scoped": True}
    assert {n for n, row in rows.items() if row["on_frontier"]} == {"deny_all", "violation_patch", "scoped_trace"}
    assert r["selected"] == "scoped_trace"
    # The cheapest patch overfits: it blocks the attack it saw but not a sibling attack in the same task.
    assert cell(rows["violation_patch"], "development", "transfer_prevented") == (4, 6)
    assert cell(rows["violation_patch"], "held_out", "transfer_prevented") == (0, 4)
    assert cell(rows["scoped_trace"], "held_out", "transfer_prevented") == (4, 4)
    # Global policies generalise worse than per-task ones.
    g = rows["global_scoped"]
    assert cell(g, "held_out", "forbidden_effects_prevented") == (4, 5)
    assert cell(g, "held_out", "task_completion") == (7, 11) and cell(g, "held_out", "false_positive_calls") == (4, 43)


def test_four_arms_and_exact_denominators():
    arms = {a["arm"]: a["score"] for a in evolve(3)["arms"]["held_out"]}
    assert arms["unprotected baseline"]["forbidden_effects_prevented"] == {"numerator": 0, "denominator": 5, "value": 0.0}
    assert arms["blanket deny"]["task_completion"] == {"numerator": 0, "denominator": 11, "value": 0.0}
    assert arms["blanket deny"]["control_false_positives"] == {"numerator": 6, "denominator": 6, "value": 1.0}
    for name in ("manually authored", "synthesized"):
        assert arms[name]["forbidden_effects_prevented"]["numerator"] == 5 and arms[name]["task_completion"]["numerator"] == 11
    assert all(a["cost_usd"] is None for a in arms.values())


def test_selected_candidate_is_feasible_and_never_called_optimal():
    r = evolve(3)
    chosen = next(s for s in r["strategies"] if s["selected"])
    assert chosen["feasible"] and chosen["on_frontier"]
    assert "optimal" not in json.dumps(r).replace("proof of optimality", "").replace("not a proven optimum", "").lower().replace("globally", "")


def test_evolution_is_identical_across_processes_apart_from_timings(tmp_path):
    def run(seed):
        out = tmp_path / f"evo-{seed}.json"
        subprocess.run([sys.executable, "-m", "necroshield", "evolve", "--variants", "3", "--out", str(out)], cwd=BACKEND,
                       check=True, capture_output=True, env={**os.environ, "PYTHONHASHSEED": seed})
        text = json.loads(out.read_text())

        def strip(node):
            if isinstance(node, dict):
                return {k: strip(v) for k, v in node.items() if k != "median_ms"}
            return [strip(v) for v in node] if isinstance(node, list) else node
        return strip(text)
    assert run("1") == run("2")


def test_evolve_cli_refuses_to_overwrite(tmp_path):
    out = tmp_path / "evo.json"
    out.write_text("earlier")
    proc = subprocess.run([sys.executable, "-m", "necroshield", "evolve", "--out", str(out)], cwd=BACKEND,
                          capture_output=True, text=True)
    assert proc.returncode == 1 and out.read_text() == "earlier"


def test_theatre_is_bounded_and_explains_every_candidate():
    t = theatre("data_exfiltration", 3)
    assert t["red_team"]["baseline_attack_succeeded"] and t["red_team"]["violating_calls"]
    assert t["scenario"]["peer_attacks"] == ["tool_response_injection"]
    assert {c["name"] for c in t["candidates"]} == {"allow_all", "deny_all", "tool_allowlist", "violation_patch", "scoped_trace", "exact_trace"}
    assert t["selected"] == "scoped_trace" and any(d["decisive"] for d in t["counterfactual"])
    assert all(c["rejection"] for c in t["candidates"] if not c["feasible"])
    with pytest.raises(KeyError):
        theatre("benign_invoice")


def test_approved_candidate_runs_as_a_custom_policy_with_verifiable_evidence(verifier):
    scenario = CORPUS["unauthorized_record_access"]
    pair = run_pair(scenario, candidate_policy("unauthorized_record_access", "scoped_trace"))
    assert pair.policy_source == "custom" and not pair.protected.outcome.attack_succeeded
    assert verifier.verify(pair.export()) == []
    with pytest.raises(KeyError):
        candidate_policy("unauthorized_record_access", "global_scoped")
