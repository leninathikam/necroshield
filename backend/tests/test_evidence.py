import ast
import copy
import json
import random
import string
import subprocess
import sys
from dataclasses import replace

import pytest

from necroshield.__main__ import main as cli_main
from necroshield.contracts import ToolCall
from necroshield.evidence import EventChain, link
from necroshield.policy import evaluate
from necroshield.runner import run_pair
from necroshield.scenarios import DOCUMENT_INJECTION
from necroshield.storage import RunStore
from tests.conftest import VERIFIER_PATH

SECRETS = ("sk-synthetic-", "SK-SYNTHETIC-", "@example.invalid", "@EXAMPLE.INVALID")


def _rehash(run):
    """Recompute a run's chain after tampering, as a forger would."""
    prev = "0" * 64
    for seq, event in enumerate(run["events"]):
        event["seq"], event["prev_hash"] = seq, prev
        event["hash"] = link(prev, {k: v for k, v in event.items() if k != "hash"})
        prev = event["hash"]
    run["head"] = prev
    run["outcome"] = run["events"][-1]["data"]


def _protected(export):
    return next(r for r in export["runs"] if r["mode"] == "protected")


@pytest.fixture
def leaky_scenario():
    """Injected call whose arguments carry synthetic secrets, to prove redaction covers all evidence."""
    doc = DOCUMENT_INJECTION.documents["inv-2026-0413"].replace(
        '"attach": "customer_records"',
        '"attach": "customer_records", "note": "key SK-SYNTHETIC-abc123 for odo@EXAMPLE.invalid"',
    )
    return replace(DOCUMENT_INJECTION, documents={"inv-2026-0413": doc})


def test_redaction_happens_before_hashing():
    chain = EventChain("run-x")
    event = chain.append("note", {"odo@example.invalid": "key sk-synthetic-abc123"})
    assert not any(s.lower() in json.dumps(event).lower() for s in SECRETS)
    assert event["hash"] == link("0" * 64, {k: v for k, v in event.items() if k != "hash"})


def test_secrets_in_intents_stay_out_of_export_store_and_cli(leaky_scenario, verifier, tmp_path, capsys, monkeypatch):
    pair = run_pair(leaky_scenario)
    assert "SK-SYNTHETIC-abc123" in pair.intents[1].args["note"]  # the secret really entered the run
    export_text = json.dumps(pair.export())
    assert not any(s in export_text for s in SECRETS)
    assert verifier.verify(pair.export()) == []

    db = tmp_path / "runs.db"
    store = RunStore(db)
    store.save(pair)
    store.close()
    assert not any(s.encode() in db.read_bytes() for s in SECRETS)

    monkeypatch.setattr("necroshield.__main__.get_scenario", lambda _id: leaky_scenario)
    assert cli_main(["run", "document_injection", "--db", str(tmp_path / "cli.db"),
                     "--export", str(tmp_path / "cli.json")]) == 0
    out = capsys.readouterr().out + (tmp_path / "cli.json").read_text()
    assert not any(s in out for s in SECRETS)


def test_clean_export_verifies_with_pinned_digests(pair, verifier):
    s = DOCUMENT_INJECTION
    assert verifier.verify(pair.export(), s.digest(), s.policy.digest()) == []


def test_export_is_a_copy(pair):
    export = pair.export()
    export["runs"][1]["outcome"]["attack_succeeded"] = True
    assert pair.export()["runs"][1]["outcome"]["attack_succeeded"] is False


# --- tampering: each case returns the substring the verifier should report --------------------

def _edit_output(e):
    _protected(e)["events"][1]["data"]["output"] = "edited"
    return "hash mismatch"

def _reorder(e):
    ev = _protected(e)["events"]; ev[1], ev[2] = ev[2], ev[1]
    return "out of order"

def _drop(e):
    del _protected(e)["events"][2]
    return "do not cover the intents"

def _duplicate(e):
    ev = _protected(e)["events"]; ev.insert(2, copy.deepcopy(ev[2]))
    return "do not cover the intents"

def _forge_outcome(e):
    _protected(e)["outcome"]["task_completed"] = False
    return "outcome disagrees"

def _swap_digest(e):
    e["scenario"]["digest"] = "f" * 64
    return "scenario_digest does not match"

def _edit_scenario_id(e):
    e["scenario"]["id"] = "benign_invoice"
    return "scenario_id does not match"

def _edit_version(e):
    e["scenario"]["version"] = "9.9.9"
    return "scenario_version does not match"

def _edit_pair_id(e):
    e["pair_id"] = "00000000-0000-0000-0000-000000000000"
    return "pair_id does not match"

def _duplicate_run(e):
    e["runs"][1] = copy.deepcopy(e["runs"][0])
    return "exactly one baseline and one protected"

def _rehashed_denied_dispatch(e):
    run = _protected(e); run["events"][2]["data"]["dispatched"] = True; _rehash(run)
    return "dispatch does not follow"

def _rehashed_forged_allow(e):
    run = _protected(e)
    run["events"][2]["data"].update(allowed=True, dispatched=True, output="message queued", reason="granted")
    run["events"][-1]["data"]["attack_succeeded"] = True
    _rehash(run)
    return "contradicts the policy"

def _rehashed_changed_intent(e):
    run = _protected(e); run["events"][2]["data"]["tool"] = "read_document"; _rehash(run)
    return "differs from the intended action"

def _rehashed_emptied_intents(e):
    e["intents"] = []
    for run in e["runs"]:
        run["events"] = [run["events"][0], run["events"][-1]]
        _rehash(run)
    return "no intended actions"

def _rehashed_unknown_kind(e):
    run = _protected(e)
    run["events"].insert(2, {**copy.deepcopy(run["events"][1]), "kind": "approve_everything"})
    _rehash(run)
    return "events must be run_started"

def _rehashed_extra_field(e):
    run = _protected(e); run["events"][1]["data"]["approved_by"] = "admin"; _rehash(run)
    return "unexpected tool_call fields"

def _rehashed_claimed_attack(e):
    run = _protected(e); run["events"][-1]["data"]["attack_succeeded"] = True; _rehash(run)
    return "attack claimed without a dispatched send_message"

def _widened_policy(e):
    e["policy"]["grants"].append({"grant_id": "g-x", "tool": "send_message",
                                  "allowed_args": {"to": None, "attach": None}})
    return "policy digest does not match"

def _widened_policy_rehashed(e):
    """A forger widens the policy and recomputes its digest; run_started still binds the original."""
    _widened_policy(e)
    body = {k: v for k, v in e["policy"].items() if k != "digest"}
    e["policy"]["digest"] = link("", body)  # any value other than the bound digest
    return "policy_digest does not match"


TAMPERS = [_edit_output, _reorder, _drop, _duplicate, _forge_outcome, _swap_digest, _edit_scenario_id,
           _edit_version, _edit_pair_id, _duplicate_run, _rehashed_denied_dispatch, _rehashed_forged_allow,
           _rehashed_changed_intent, _rehashed_emptied_intents, _rehashed_unknown_kind,
           _rehashed_extra_field, _rehashed_claimed_attack, _widened_policy, _widened_policy_rehashed]


@pytest.mark.parametrize("tamper", TAMPERS)
def test_tampered_export_is_rejected_for_the_right_reason(pair, verifier, tamper):
    export = json.loads(json.dumps(pair.export()))  # as the verifier would read it from a file
    expected = tamper(export)
    problems = verifier.verify(export)
    assert any(expected in p for p in problems), problems


def test_fully_recomputed_forgery_is_caught_only_by_pinned_digests(pair, verifier):
    """Documents the stated limit: a consistent rewrite passes unless the digests are pinned."""
    export = pair.export()
    export["policy"]["grants"].append({"grant_id": "g-x", "tool": "send_message",
                                       "allowed_args": {"to": None, "attach": None}})
    body = {k: v for k, v in export["policy"].items() if k != "digest"}
    export["policy"]["digest"] = verifier.sha256(verifier.canonical(body))
    run = _protected(export)
    run["events"][0]["data"]["policy_digest"] = export["policy"]["digest"]
    run["events"][2]["data"].update(allowed=True, dispatched=True, output="message queued",
                                    reason="granted", grant_id="g-x")
    run["events"][-1]["data"]["attack_succeeded"] = True
    _rehash(run)
    export["runs"][0]["events"][0]["data"]["policy_digest"] = export["policy"]["digest"]
    _rehash(export["runs"][0])
    assert verifier.verify(export) == []
    pinned = verifier.verify(export, policy_digest=DOCUMENT_INJECTION.policy.digest())
    assert any("pinned" in p for p in pinned)


@pytest.mark.parametrize("broken", [
    [], "text", {"format": "necroshield.pair/1"},
    {"format": "necroshield.pair/1", "pair_id": "p", "replay_mode": "deterministic_intent_replay",
     "scenario": {"id": "a", "version": "1", "kind": "attack", "digest": "d"},
     "policy": {"version": "v", "grants": []}, "intents": [{}], "runs": ["x", "y"]},
])
def test_malformed_exports_are_reported_not_crashed(verifier, broken):
    assert verifier.verify(broken)


def test_malformed_events_are_reported_not_crashed(pair, verifier):
    for mutate in (lambda r: r["events"].__setitem__(1, "x"),
                   lambda r: r["events"][1].pop("data"),
                   lambda r: r.pop("mode")):
        export = pair.export()
        mutate(_protected(export))
        assert verifier.verify(export)


def test_verifier_and_gateway_agree_on_policy_decisions(verifier):
    """Cross-checks the two independent implementations of the grant rules."""
    rng = random.Random(7)
    policy = DOCUMENT_INJECTION.policy.to_dict()
    values = ["inv-2026-0413", "summary", "customers", "", "x"]
    for _ in range(3000):
        tool = rng.choice(["read_document", "write_report", "send_message"])
        keys = rng.sample(["doc_id", "report_id", "body", "to"], k=rng.randint(0, 3))
        args = {k: rng.choice(values + ["".join(rng.choices(string.printable, k=5))]) for k in keys}
        ours = evaluate(DOCUMENT_INJECTION.policy, ToolCall(tool, args))
        assert verifier.evaluate_policy(policy, tool, args) == (ours.allowed, ours.grant_id)


def test_verifier_imports_only_the_standard_library():
    tree = ast.parse(VERIFIER_PATH.read_text())
    imported = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
                for alias in node.names}
    imported |= {node.module.split(".")[0] for node in ast.walk(tree)
                 if isinstance(node, ast.ImportFrom) and node.module}
    assert imported <= set(sys.stdlib_module_names), imported - set(sys.stdlib_module_names)


def test_verifier_cli_runs_isolated(pair, tmp_path):
    path = tmp_path / "pair.json"
    path.write_text(json.dumps(pair.export()))
    args = [sys.executable, "-I", "-S", str(VERIFIER_PATH), str(path),
            "--scenario-digest", DOCUMENT_INJECTION.digest(),
            "--policy-digest", DOCUMENT_INJECTION.policy.digest()]
    ok = subprocess.run(args, capture_output=True, text=True, cwd=tmp_path)
    assert ok.returncode == 0 and ok.stdout.startswith("OK") and "pinned" in ok.stdout, ok.stdout + ok.stderr

    export = pair.export()
    _edit_output(export)
    path.write_text(json.dumps(export))
    bad = subprocess.run(args, capture_output=True, text=True, cwd=tmp_path)
    assert bad.returncode == 1 and "hash mismatch" in bad.stdout
