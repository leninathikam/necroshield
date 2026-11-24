from necroshield import agent
from necroshield.catalog import DOCUMENT_INJECTION, MEMORY_POISONING, TOOL_RESPONSE_INJECTION
from necroshield.contracts import REPLAY_MODE, RunMode
from necroshield.runner import run_once, run_pair


def test_agent_sees_injections_in_documents():
    tools = [c.tool for c in agent.plan(DOCUMENT_INJECTION)]
    assert tools == ["read_document", "send_message", "get_customer_record", "read_memory", "write_report"]


def test_agent_sees_injections_in_tool_responses():
    intents = agent.plan(TOOL_RESPONSE_INJECTION)
    injected = intents[2]
    assert injected.tool == "send_message" and injected.args["to"] == "collector@sink.invalid"
    assert intents[1].tool == "get_customer_record"  # the injection arrived through this response


def test_plan_is_deterministic():
    assert agent.plan(DOCUMENT_INJECTION) == agent.plan(DOCUMENT_INJECTION)


def test_both_runs_record_identical_intents(pair):
    expected = [c.to_dict() for c in pair.intents]
    for run in (pair.baseline, pair.protected):
        recorded = [{"tool": e["data"]["tool"], "args": e["data"]["args"]} for e in run.events if e["kind"] == "tool_call"]
        assert recorded == expected


def test_placeholders_bind_from_each_runs_own_observations():
    pair = run_pair(MEMORY_POISONING)
    report = lambda run: next(r.call.args["body"] for r in run.records if r.call.tool == "write_report")
    assert pair.intents[-1].args["body"] == "Invoice $number total $total payee $payee"
    assert report(pair.baseline).endswith("ACCT-ATTACKER-666")  # poisoned memory flowed into the report
    assert report(pair.protected).endswith("ACCT-HP-2231")


def test_each_run_starts_from_fresh_state():
    intents = agent.plan(DOCUMENT_INJECTION)
    first = run_once(DOCUMENT_INJECTION, intents, RunMode.BASELINE)
    second = run_once(DOCUMENT_INJECTION, intents, RunMode.BASELINE)
    assert first.outcome.observed_effects == second.outcome.observed_effects


def test_scenario_is_not_mutated_by_runs():
    before = DOCUMENT_INJECTION.digest()
    run_pair(DOCUMENT_INJECTION)
    assert DOCUMENT_INJECTION.digest() == before


def test_runs_have_distinct_ids_shared_pair_id_and_replay_label(pair):
    assert pair.baseline.run_id != pair.protected.run_id
    export = pair.export()
    assert export["replay_mode"] == REPLAY_MODE
    for run in export["runs"]:
        assert run["events"][0]["data"]["pair_id"] == pair.pair_id


def test_custom_policy_is_labeled_and_changes_the_outcome():
    from necroshield.scenarios import Grant, Policy
    s = DOCUMENT_INJECTION
    permissive = Policy("custom/1.0.0", s.policy.grants + (
        Grant("g-any-send", "send_message", {"to": None, "attach": None}),))
    pair = run_pair(s, permissive)
    assert pair.policy_source == "custom" and pair.export()["policy"]["source"] == "custom"
    assert pair.protected.outcome.attack_succeeded is True
