"""Semantic regression checks for the standalone evidence verifier."""

from datetime import datetime
import importlib.util
from pathlib import Path

import pytest

from necroshield.engine import execute_pair
from necroshield.evidence import export_pair
from necroshield.scenarios import DOCUMENT_INJECTION


@pytest.fixture(scope="module")
def verifier():
    script = Path(__file__).resolve().parents[2] / "scripts" / "verify_evidence.py"
    specification = importlib.util.spec_from_file_location("standalone_necroshield_verifier", script)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def rehash_trace(verifier, data, mode):
    previous = "0" * 64
    for event in data[mode]["events"]:
        event["previous_hash"] = previous
        body = {key: value for key, value in event.items() if key != "hash"}
        body["timestamp"] = datetime.fromisoformat(body["timestamp"].replace("Z", "+00:00")).isoformat()
        event["hash"] = verifier.digest(body)
        previous = event["hash"]
    rehash_export(verifier, data)


def rehash_export(verifier, data):
    data["export_digest"] = verifier.digest({key: value for key, value in data.items() if key != "export_digest"})


def test_actual_redacted_fixture_export_passes_independent_verification(verifier):
    verifier.verify(export_pair(execute_pair(DOCUMENT_INJECTION)))


@pytest.mark.parametrize("mode,replacement", [("protected", "bypass"), ("baseline", "allow")])
def test_mode_contradicting_policy_decision_rejected_even_with_valid_hashes(verifier, mode, replacement):
    data = export_pair(execute_pair(DOCUMENT_INJECTION))
    decision = next(event for event in data[mode]["events"] if event["kind"] == "policy.decision")
    decision["decision"] = replacement
    rehash_trace(verifier, data, mode)
    with pytest.raises(ValueError):
        verifier.verify(data)


def test_top_level_effects_must_match_completion_event_even_with_valid_digest(verifier):
    data = export_pair(execute_pair(DOCUMENT_INJECTION))
    data["protected"]["effects"]["sink_received"] = True
    rehash_export(verifier, data)
    with pytest.raises(ValueError):
        verifier.verify(data)
