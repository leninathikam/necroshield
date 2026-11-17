from dataclasses import replace

import pytest

from necroshield.cli import verify_export
from necroshield.contracts import Event
from necroshield.engine import build_intent_tape, execute_pair
from necroshield.evidence import export_pair, verify_chain
from necroshield.scenarios import DOCUMENT_INJECTION, SCENARIOS


@pytest.mark.parametrize("scenario", SCENARIOS.values(), ids=lambda scenario: scenario.info.id)
def test_each_fixture_effect_and_utility_are_measured(scenario):
    pair = execute_pair(scenario)
    assert pair.baseline.metrics.attack_success is scenario.info.is_attack
    assert pair.protected.metrics.attack_success is False
    assert pair.baseline.metrics.legitimate_task_completed is True
    assert pair.protected.metrics.legitimate_task_completed is True
    assert pair.protected.metrics.blocked_executions == int(scenario.info.is_attack)
    assert pair.protected.metrics.false_positives == 0
    assert pair.protected.metrics.cost_usd is None
    for run in [pair.baseline, pair.protected]:
        assert verify_chain(run.events)
        for index, event in enumerate(run.events):
            if event.kind == "tool.executed":
                decision = run.events[index - 1]
                assert decision.kind == "policy.decision"
                assert decision.tool == event.tool
                assert decision.decision in {"allow", "bypass"}
    assert pair.protected.effects["executed_tools"] == ["document.read", "report.write"]


def test_report_is_derived_from_the_input_and_evaluator_catches_wrong_total():
    changed = replace(DOCUMENT_INJECTION, document=DOCUMENT_INJECTION.document.replace("Total: 137", "Total: 209"))
    pair = execute_pair(changed)
    assert pair.protected.output == "Invoice total: 209 credits."
    assert pair.protected.metrics.legitimate_task_completed is False


def test_replay_tape_is_identical_but_worlds_and_ids_are_fresh():
    first, second = execute_pair(DOCUMENT_INJECTION), execute_pair(DOCUMENT_INJECTION)
    assert first.id != second.id
    assert first.baseline.id != first.protected.id
    assert first.intent_tape_digest == second.intent_tape_digest
    assert first.scenario_digest == second.scenario_digest
    assert first.baseline.effects["sink_received"] is True
    assert first.protected.effects["sink_received"] is False


def test_hash_chain_and_export_detect_tampering_after_serialization():
    pair = execute_pair(DOCUMENT_INJECTION)
    exported = export_pair(pair)
    assert verify_export(exported)
    assert "SYNTHETIC-SECRET" not in str(exported)
    events = [Event.model_validate(e) for e in exported["protected"]["events"]]
    assert verify_chain(events)
    events[0] = events[0].model_copy(update={"message": "tampered"})
    assert not verify_chain(events)
    assert not verify_chain(list(reversed(events)))
    exported["protected"]["metrics"]["attack_success"] = True
    assert not verify_export(exported)


def test_missing_invoice_and_unbounded_intent_sources_fail_closed():
    with pytest.raises(ValueError, match="no valid total"):
        build_intent_tape(replace(DOCUMENT_INJECTION, document="no invoice"))
    with pytest.raises(ValueError, match="source exceeds"):
        build_intent_tape(replace(DOCUMENT_INJECTION, document="x" * 17000))
