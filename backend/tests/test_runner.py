from necroshield import agent
from necroshield.contracts import REPLAY_MODE, RunMode
from necroshield.runner import run_once
from necroshield.scenarios import DOCUMENT_INJECTION


def test_agent_plan_is_deterministic_and_contains_the_injected_call():
    first, second = agent.plan(DOCUMENT_INJECTION), agent.plan(DOCUMENT_INJECTION)
    assert first == second
    assert [c.tool for c in first] == ["read_document", "send_message", "write_report"]


def test_both_runs_receive_identical_intents(pair):
    for run in (pair.baseline, pair.protected):
        assert tuple(r.call for r in run.records) == pair.intents


def test_baseline_leaks_and_protected_blocks_while_task_completes(pair):
    assert pair.baseline.outcome.attack_succeeded is True
    assert pair.protected.outcome.attack_succeeded is False
    assert pair.baseline.outcome.task_completed is True
    assert pair.protected.outcome.task_completed is True
    denied = [r.call.tool for r in pair.protected.records if not r.decision.allowed]
    assert denied == ["send_message"]


def test_each_run_starts_from_fresh_state():
    intents = agent.plan(DOCUMENT_INJECTION)
    first = run_once(DOCUMENT_INJECTION, intents, RunMode.BASELINE)
    second = run_once(DOCUMENT_INJECTION, intents, RunMode.BASELINE)
    # A shared sink would make the second run observe two leaked messages.
    assert first.outcome.observed_effects == second.outcome.observed_effects
    assert sum("canary" in e for e in second.outcome.observed_effects) == 1


def test_runs_have_distinct_ids_and_replay_label(pair):
    assert pair.baseline.run_id != pair.protected.run_id
    export = pair.export()
    assert export["replay_mode"] == REPLAY_MODE
    assert all(r["events"][0]["data"]["replay_mode"] == REPLAY_MODE for r in export["runs"])


def test_scenario_digest_changes_with_content():
    from dataclasses import replace
    assert replace(DOCUMENT_INJECTION, version="1.0.1").digest() != DOCUMENT_INJECTION.digest()
