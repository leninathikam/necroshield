import copy
import json
import subprocess
import sys

import pytest

from necroshield.contracts import canonical_json
from necroshield.evidence import EventChain, link
from tests.conftest import VERIFIER_PATH


def _rehash(run):
    """Recompute a run's chain after tampering, as a naive forger would."""
    prev = "0" * 64
    for seq, event in enumerate(run["events"]):
        event["seq"], event["prev_hash"] = seq, prev
        event["hash"] = link(prev, {k: v for k, v in event.items() if k != "hash"})
        prev = event["hash"]
    run["head"] = prev


def test_redaction_happens_before_hashing():
    chain = EventChain("run-x")
    event = chain.append("note", {"text": "mail odo@example.invalid key sk-synthetic-abc123"})
    assert "example.invalid" not in event["data"]["text"] and "sk-synthetic" not in event["data"]["text"]
    assert event["hash"] == link("0" * 64, {k: v for k, v in event.items() if k != "hash"})


def test_export_contains_no_unredacted_synthetic_secrets(pair):
    text = canonical_json(pair.export())
    assert "sk-synthetic-" not in text and "@example.invalid" not in text


def test_clean_export_verifies(pair, verifier):
    assert verifier.verify(pair.export()) == []


def _protected(export):
    return next(r for r in export["runs"] if r["mode"] == "protected")


def _edit_output(e):
    _protected(e)["events"][1]["data"]["output"] = "edited"

def _reorder(e):
    ev = _protected(e)["events"]; ev[1], ev[2] = ev[2], ev[1]

def _drop(e):
    del _protected(e)["events"][2]

def _duplicate(e):
    ev = _protected(e)["events"]; ev.insert(2, copy.deepcopy(ev[2]))

def _forge_outcome(e):
    _protected(e)["outcome"]["task_completed"] = False

def _swap_digest(e):
    e["scenario"]["digest"] = "f" * 64

def _duplicate_run(e):
    e["runs"][1] = copy.deepcopy(e["runs"][0])

def _rehashed_denied_dispatch(e):
    run = _protected(e)
    run["events"][2]["data"]["dispatched"] = True
    _rehash(run)

def _rehashed_changed_intent(e):
    run = _protected(e)
    run["events"][2]["data"]["tool"] = "read_document"
    _rehash(run)


@pytest.mark.parametrize("tamper", [
    _edit_output, _reorder, _drop, _duplicate, _forge_outcome, _swap_digest,
    _duplicate_run, _rehashed_denied_dispatch, _rehashed_changed_intent,
])
def test_tampered_export_is_rejected(pair, verifier, tamper):
    export = pair.export()
    tamper(export)
    assert verifier.verify(export), f"{tamper.__name__} was not detected"


def test_verifier_runs_standalone_without_application_imports(pair, tmp_path):
    source = VERIFIER_PATH.read_text()
    assert "necroshield" not in source.replace("NecroShield", "").replace("necroshield.pair/1", "")
    path = tmp_path / "pair.json"
    path.write_text(json.dumps(pair.export()))
    ok = subprocess.run([sys.executable, "-I", str(VERIFIER_PATH), str(path)],
                        capture_output=True, text=True, cwd=tmp_path)
    assert ok.returncode == 0 and ok.stdout.startswith("OK"), ok.stdout + ok.stderr

    export = pair.export()
    _edit_output(export)
    path.write_text(json.dumps(export))
    bad = subprocess.run([sys.executable, "-I", str(VERIFIER_PATH), str(path)],
                         capture_output=True, text=True, cwd=tmp_path)
    assert bad.returncode == 1 and "hash mismatch" in bad.stdout
