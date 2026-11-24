"""Hypothesis property tests. Skipped (and reported as skipped) where Hypothesis is not installed."""

import copy
import json

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st  # noqa: E402

from necroshield import tools  # noqa: E402
from necroshield.catalog import REGISTRY  # noqa: E402
from necroshield.contracts import RunMode, ToolCall  # noqa: E402
from necroshield.policy import evaluate  # noqa: E402
from necroshield.runner import run_once, run_pair  # noqa: E402
from necroshield.verification import verify_export  # noqa: E402

TEXT = st.text(alphabet=st.characters(min_codepoint=32, max_codepoint=0x2FFF), max_size=40)
TOOL = st.sampled_from(sorted(tools.TOOL_NAMES) + ["exec_shell", "delete_all"])
ARG = st.sampled_from(["path", "customer_id", "report_id", "body", "to", "attach", "key", "value", "cmd"])
CALL = st.builds(lambda t, a: ToolCall(t, a), TOOL, st.dictionaries(ARG, TEXT, max_size=4))
SCENARIO = st.sampled_from(sorted(REGISTRY))


@settings(max_examples=300, deadline=None)
@given(SCENARIO, st.lists(CALL, max_size=8))
def test_denied_calls_never_dispatch_and_leave_no_side_effects(scenario_id, calls):
    scenario = REGISTRY[scenario_id]
    result = run_once(scenario, tuple(calls), RunMode.PROTECTED)
    for record in result.records:
        assert record.dispatched == record.decision.allowed
        if not record.decision.allowed:
            assert record.output is None and record.error is None
    allowed_tools = [r.call.tool for r in result.records if r.decision.allowed and r.call.tool in tools.TOOLS]
    denied = [r for r in result.records if not r.decision.allowed]
    assert all(evaluate(scenario.policy, r.call).allowed is False for r in denied)
    assert len(allowed_tools) <= len(calls)


@settings(max_examples=50, deadline=None)
@given(SCENARIO)
def test_paired_runs_share_identical_intents(scenario_id):
    pair = run_pair(REGISTRY[scenario_id])
    for run in (pair.baseline, pair.protected):
        recorded = [{"tool": e["data"]["tool"], "args": e["data"]["args"]} for e in run.events if e["kind"] == "tool_call"]
        assert recorded == [c.to_dict() for c in pair.intents]


@settings(max_examples=200, deadline=None)
@given(SCENARIO, st.data())
def test_any_single_event_edit_fails_verification(scenario_id, data):
    export = json.loads(json.dumps(run_pair(REGISTRY[scenario_id]).export()))
    run = data.draw(st.sampled_from(export["runs"]))
    event = data.draw(st.sampled_from(run["events"]))
    field = data.draw(st.sampled_from(sorted(event["data"])))
    tampered = copy.deepcopy(event["data"][field])
    event["data"][field] = {"edited": tampered}
    assert verify_export(export)
