import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from necroshield.patches import check_patch, compile_patch

BACKEND = Path(__file__).resolve().parents[1]


def fresh(*args, **kwargs):
    return json.loads(json.dumps(compile_patch(*args, **kwargs)))


@pytest.fixture(scope="module")
def transfer_patch():
    """A patch built for one attack is deployed; a sibling attack gets through; compile the fix."""
    return fresh("data_exfiltration", "violation_patch", "scoped_trace", base_from="tool_response_injection")


def test_the_observed_failure_is_a_real_one(transfer_patch):
    assert transfer_patch["failure"]["observed_effects"][0].startswith("attack")
    assert transfer_patch["failure"]["calls_let_through"] == [
        {"tool": "send_message", "args": {"to": "billing@finance.invalid", "attach": "all_customers"}}]
    assert transfer_patch["activation"] == {"status": "proposed", "applied": False, "requires": "human approval"}


def test_every_regression_case_passes_and_both_splits_are_covered(transfer_patch):
    assert transfer_patch["all_cases_pass"] and all(r["passed"] for r in transfer_patch["results"])
    assert {r["split"] for r in transfer_patch["results"]} == {"development", "held_out"}
    assert [r["id"] for r in transfer_patch["results"]][:2] == ["failure-reproduces-on-base", "fixed-on-proposed"]


def test_aggregate_shows_the_fix_without_regressions_elsewhere(transfer_patch):
    dev, held = transfer_patch["aggregate"]["development"], transfer_patch["aggregate"]["held_out"]
    assert dev["before"]["forbidden_effects_prevented"]["numerator"] == 4 and dev["after"]["forbidden_effects_prevented"]["numerator"] == 5
    assert held["before"]["forbidden_effects_prevented"] == held["after"]["forbidden_effects_prevented"]
    for part in (dev, held):
        assert part["after"]["task_completion"]["numerator"] >= part["before"]["task_completion"]["numerator"]
        assert part["after"]["false_positive_calls"]["numerator"] == 0


def test_patch_can_be_rechecked_from_its_own_contents(transfer_patch):
    assert check_patch(transfer_patch) == []


@pytest.mark.parametrize("tamper, expected", [
    (lambda p: p["proposed"]["policy"]["grants"].pop(), "embedded policy digest"),
    (lambda p: p["operations"].pop(), "operations do not follow"),
    (lambda p: p["scenario"].update(digest="0" * 64), "scenario digest differs"),
    (lambda p: p["regression_spec"][1]["expect"].update(attack_succeeded=True), "attack_succeeded"),
    (lambda p: p["activation"].update(applied=True), "activation must be proposed"),
    (lambda p: p.update(patch_id="0" * 16), "patch id"),
    (lambda p: p["results"].pop(), "recorded results"),
    (lambda p: p.update(format="x"), "not a necroshield.patch/1"),
])
def test_tampered_patches_are_rejected(transfer_patch, tamper, expected):
    broken = copy.deepcopy(transfer_patch)
    tamper(broken)
    assert any(expected in problem for problem in check_patch(broken)), check_patch(broken)


def test_no_failure_means_no_patch():
    with pytest.raises(ValueError, match="no failure observed"):
        compile_patch("document_injection", "tool_allowlist")
    with pytest.raises(ValueError):
        compile_patch("data_exfiltration", "violation_patch")  # built from this very attack: already stopped


@pytest.mark.parametrize("args", [("benign_invoice",), ("nope",), ("data_exfiltration", "global_scoped"),
                                  ("data_exfiltration", "violation_patch", "scoped_trace", "document_injection")])
def test_invalid_inputs_are_key_errors(args):
    with pytest.raises(KeyError):
        compile_patch(*args)


def test_a_failure_with_variants_gets_variant_cases():
    patch = compile_patch("document_injection", "allow_all")
    assert any(c["id"].startswith("variant-") and c["expect"]["attack_succeeded"] is False for c in patch["regression_spec"])
    assert check_patch(json.loads(json.dumps(patch))) == []


def test_markdown_report_is_human_readable(transfer_patch):
    md = transfer_patch["report_markdown"]
    assert md.startswith("# Security patch") and "Status: **proposed**" in md and "| fixed-on-proposed |" in md


def test_patch_cli_round_trip(tmp_path):
    out = tmp_path / "patch.json"
    run = lambda *a: subprocess.run([sys.executable, "-m", "necroshield", *a], cwd=BACKEND, capture_output=True, text=True)  # noqa: E731
    made = run("patch", "data_exfiltration", "--base", "violation_patch", "--base-from", "tool_response_injection", "--out", str(out))
    assert made.returncode == 0 and "regression cases pass" in made.stdout
    assert run("check-patch", str(out)).returncode == 0
    assert run("patch", "data_exfiltration", "--base", "violation_patch", "--base-from", "tool_response_injection", "--out", str(out)).returncode == 1
    broken = json.loads(out.read_text())
    broken["proposed"]["policy"]["grants"].pop()
    out.write_text(json.dumps(broken))
    assert run("check-patch", str(out)).returncode == 1
