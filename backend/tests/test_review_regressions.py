"""Regression tests for findings from the independent review of the web-platform change set.
Each test names the finding it covers (see evidence/final-verification.md)."""

import ast
import copy
import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from necroshield import agent
from necroshield.catalog import DOCUMENT_INJECTION, REGISTRY
from necroshield.contracts import ToolCall
from necroshield.evidence import link
from necroshield.metrics import BUNDLE_FORMAT, summarize
from necroshield.runner import run_pair
from necroshield.scenarios import Check, Grant
from necroshield.storage import RunStore, StorageFull

PACKAGE = Path(__file__).resolve().parents[1] / "necroshield"


def _export(scenario=DOCUMENT_INJECTION):
    return json.loads(json.dumps(run_pair(scenario).export()))


def _run(export, mode):
    return next(r for r in export["runs"] if r["mode"] == mode)


def _rehash(run):
    prev = "0" * 64
    for seq, event in enumerate(run["events"]):
        event["seq"], event["prev_hash"] = seq, prev
        event["hash"] = link(prev, {k: v for k, v in event.items() if k != "hash"})
        prev = event["hash"]
    run["head"] = prev
    run["outcome"] = run["events"][-1]["data"]


def test_v1_erasing_an_observed_attack_is_rejected(verifier):
    export = _export()
    baseline = _run(export, "baseline")
    done = baseline["events"][-1]["data"]
    done["attack_succeeded"] = False
    done["observed_effects"] = [e for e in done["observed_effects"] if not e.startswith("attack")]
    _rehash(baseline)
    assert any("derived from chained effects" in p for p in verifier.verify(export))


def test_v1_bound_args_must_follow_from_the_intent(verifier):
    export = _export()
    protected = _run(export, "protected")
    call = protected["events"][1]["data"]  # read_document, no placeholders
    call["bound_args"] = {"path": "hr/payroll-2026"}
    _rehash(protected)
    assert any("bound_args do not follow" in p for p in verifier.verify(export))


def test_v1_effects_must_match_arguments(verifier):
    export = _export()
    protected = _run(export, "protected")
    protected["events"][1]["data"]["effects"]["reads"] = ["document:hr/payroll-2026"]
    _rehash(protected)
    assert any("effects do not match" in p for p in verifier.verify(export))


def test_v1_denied_call_with_effects_is_rejected(verifier):
    export = _export()
    protected = _run(export, "protected")
    protected["events"][2]["data"]["effects"]["sink"] = [{"to": "collector@sink.invalid", "body": "x"}]
    _rehash(protected)
    assert any("changed state without a successful dispatch" in p for p in verifier.verify(export))


@pytest.mark.parametrize("value", ["yes", 1, None])
def test_v1_outcome_fields_must_be_booleans(verifier, value):
    export = _export()
    protected = _run(export, "protected")
    protected["events"][-1]["data"]["attack_succeeded"] = value
    _rehash(protected)
    assert verifier.verify(export)


def test_v2_relabelled_scenario_fails_against_its_own_digest(verifier):
    export = _export()
    export["scenario"].update(id="benign_invoice", kind="control", attack_checks=[])
    problems = verifier.verify(export, DOCUMENT_INJECTION.digest(), DOCUMENT_INJECTION.policy.digest())
    assert any("does not match the scenario digest" in p for p in problems)


def test_v3_single_pair_pins_do_not_silently_apply_to_bundles(verifier):
    pairs = [_export(s) for s in REGISTRY.values()]
    bundle = {"format": BUNDLE_FORMAT, "summary": summarize(pairs), "pairs": pairs}
    assert verifier.verify_any(bundle, "0" * 64, "1" * 64) == [
        "single-pair digest flags do not apply to bundles or live runs; use --pins"]


def _pins():
    return {s.scenario_id: {"scenario_digest": s.digest(), "policy_digest": s.policy.digest()} for s in REGISTRY.values()}


def test_v4_pinned_bundle_must_be_complete_and_default(verifier):
    pairs = [_export(s) for s in REGISTRY.values()]
    full = {"format": BUNDLE_FORMAT, "summary": summarize(pairs), "pairs": pairs}
    assert verifier.verify_bundle(full, _pins()) == []
    subset = {"format": BUNDLE_FORMAT, "summary": summarize(pairs[:1]), "pairs": pairs[:1]}
    assert any("differ from the pinned set" in p for p in verifier.verify_bundle(subset, _pins()))


def test_v4_custom_policy_relabelled_as_default_fails_pins(verifier):
    from necroshield.scenarios import Policy
    weak = Policy("custom/1.0.0", DOCUMENT_INJECTION.policy.grants + (
        Grant("g-any-send", "send_message", {"to": None, "attach": None}),))
    export = json.loads(json.dumps(run_pair(DOCUMENT_INJECTION, weak).export()))
    export["policy"]["source"] = "scenario_default"
    assert any("policy digest differs from the pinned value" in p for p in verifier.verify_any(export, pins=_pins()))


def test_v6_lone_surrogate_is_reported_not_raised(verifier):
    export = _export()
    _run(export, "protected")["events"][1]["data"]["output"] = "\ud800"
    problems = verifier.verify(export)
    assert problems and any("surrogate" in p for p in problems)


def test_v6_floats_in_events_are_rejected(verifier):
    export = _export()
    protected = _run(export, "protected")
    protected["events"][1]["data"]["intent_index"] = 0.0
    _rehash(protected)
    assert verifier.verify(export)


def test_l2_lone_surrogates_cannot_enter_tool_calls():
    with pytest.raises(ValueError):
        ToolCall("read_document", {"path": "\ud800"})


@pytest.mark.parametrize("make", [
    lambda: Grant("g-x", "write_report", {"report_id": ("summary",), "body": ("key sk-synthetic-abc",)}),
    lambda: Grant("g-x", "send_message", {"to": ("odo@example.invalid",)}),
    lambda: Check("sink_contains", {"value": "sk-synthetic-zz"}, "x"),
])
def test_r1_r2_secret_shaped_policy_and_check_values_are_rejected(make):
    with pytest.raises(ValueError):
        make()


def test_f1_injected_lines_match_whole_source_lines():
    for scenario in REGISTRY.values():
        texts = list(scenario.documents.values()) + list(scenario.customer_records.values())
        for text in texts:
            lines = set(text.split("\n"))
            for match in agent.INJECTED_CALL.finditer(text):
                assert match.group(0) in lines


def test_g1_tool_functions_and_override_are_confined():
    users_fn, users_override = set(), set()
    for path in PACKAGE.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "_fn":
                users_fn.add(path.name)
            if isinstance(node, ast.keyword) and node.arg == "_counterfactual_override":
                users_override.add(path.name)
    assert users_fn == {"tools.py"}
    assert users_override == {"runner.py"}


def test_a3_malformed_stored_rows_are_reported_not_raised(tmp_path):
    db = tmp_path / "runs.db"
    store = RunStore(db)
    pair = run_pair(DOCUMENT_INJECTION)
    store.save(pair)
    store.close()
    raw = sqlite3.connect(db)
    raw.execute("DROP TRIGGER pairs_no_update")
    raw.execute("UPDATE pairs SET export_json = 'not json'")
    raw.commit()
    raw.close()
    store = RunStore(db)
    [stored] = store.recent()
    assert not stored.verified and stored.problems == ["stored export is not valid JSON"]
    store.close()


def test_a4_stored_heads_are_cross_checked(tmp_path):
    db = tmp_path / "runs.db"
    store = RunStore(db)
    pair = run_pair(DOCUMENT_INJECTION)
    store.save(pair)
    store.close()
    raw = sqlite3.connect(db)
    raw.execute("DROP TRIGGER runs_no_update")
    raw.execute("UPDATE runs SET head = 'f' WHERE mode = 'protected'")
    raw.commit()
    raw.close()
    stored = RunStore(db).load(pair.pair_id)
    assert "stored run heads disagree with the export" in stored.problems


def test_a2_store_refuses_pairs_past_its_cap(tmp_path):
    store = RunStore(tmp_path / "runs.db", max_pairs=1)
    store.save(run_pair(DOCUMENT_INJECTION))
    with pytest.raises(StorageFull):
        store.save(run_pair(DOCUMENT_INJECTION))
    store.close()


def test_a7_benchmark_population_ignores_older_definitions(tmp_path):
    store = RunStore(tmp_path / "runs.db")
    old = replace(DOCUMENT_INJECTION, version="1.9.9")
    store.save(run_pair(old))
    current = {"document_injection": (DOCUMENT_INJECTION.digest(), DOCUMENT_INJECTION.policy.digest())}
    assert store.latest_default_per_scenario(current) == []
    store.save(run_pair(DOCUMENT_INJECTION))
    assert [p.export["scenario"]["version"] for p in store.latest_default_per_scenario(current)] == ["2.0.0"]
    store.close()


def test_copy_of_export_is_independent():
    export = run_pair(DOCUMENT_INJECTION).export()
    snapshot = copy.deepcopy(export)
    export["runs"][0]["events"][0]["data"]["mode"] = "x"
    assert snapshot["runs"][0]["events"][0]["data"]["mode"] == "baseline"
