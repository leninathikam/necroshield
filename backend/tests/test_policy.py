"""Policy tests. The seeded generators stand in for Hypothesis, which cannot be installed in the
current environment; each checks a property that does not restate the implementation."""

import random
import string

import pytest

from necroshield import tools
from necroshield.contracts import RunMode, ToolCall
from necroshield.policy import evaluate
from necroshield.runner import run_once
from necroshield.scenarios import DOCUMENT_INJECTION

POLICY = DOCUMENT_INJECTION.policy
GRANTED_TOOLS = {g.tool for g in POLICY.grants}
SEED = 20261124


def _text(rng: random.Random) -> str:
    return "".join(rng.choices(string.printable, k=rng.randint(0, 24)))


def _granted_example(rng: random.Random) -> ToolCall:
    """A call built from a grant: fixed values from the allow-list, free text where allowed."""
    grant = rng.choice(POLICY.grants)
    args = {k: (rng.choice(v) if v is not None else _text(rng)) for k, v in grant.allowed_args.items()}
    return ToolCall(grant.tool, args)


def test_ungranted_tool_is_denied():
    decision = evaluate(POLICY, ToolCall("send_message", {"to": "x@sink.invalid"}))
    assert not decision.allowed and "no grant" in decision.reason


@pytest.mark.parametrize("args, reason", [
    ({"doc_id": "customers"}, "outside granted scope"),
    ({"doc_id": "inv-2026-0413", "mode": "raw"}, "arguments not granted"),
    ({}, "missing argument"),
])
def test_arguments_outside_grant_are_denied(args, reason):
    decision = evaluate(POLICY, ToolCall("read_document", args))
    assert not decision.allowed and reason in decision.reason


def test_calls_built_from_grants_are_allowed_including_free_text_fields():
    rng = random.Random(SEED)
    seen = set()
    for _ in range(500):
        call = _granted_example(rng)
        decision = evaluate(POLICY, call)
        assert decision.allowed, call
        seen.add(decision.grant_id)
    assert seen == {g.grant_id for g in POLICY.grants}


def test_any_tool_without_a_grant_is_denied_whatever_its_arguments():
    rng = random.Random(SEED)
    for _ in range(500):
        tool = rng.choice(["send_message", "delete_all", "read_memory", "exec", "write_memory"])
        args = {rng.choice(["to", "doc_id", "path", "body"]): _text(rng) for _ in range(rng.randint(0, 3))}
        assert not evaluate(POLICY, ToolCall(tool, args)).allowed


def test_adding_an_argument_or_leaving_scope_turns_allow_into_deny():
    rng = random.Random(SEED)
    for _ in range(500):
        call = _granted_example(rng)
        extra = dict(call.args, **{"x_" + rng.choice(string.ascii_lowercase): _text(rng)})
        assert not evaluate(POLICY, ToolCall(call.tool, extra)).allowed
        grant = next(g for g in POLICY.grants if g.tool == call.tool)
        for name, values in grant.allowed_args.items():
            if values is not None:
                outside = dict(call.args, **{name: _text(rng) + "-out"})
                assert not evaluate(POLICY, ToolCall(call.tool, outside)).allowed


def test_matching_call_records_grant_id():
    decision = evaluate(POLICY, ToolCall("read_document", {"doc_id": "inv-2026-0413"}))
    assert decision.allowed and decision.grant_id == "g-read-invoice"


def test_denied_calls_never_reach_tool_code(monkeypatch):
    invoked = []
    for name, fn in list(tools.TOOLS.items()):
        monkeypatch.setitem(tools.TOOLS, name, lambda env, args, _n=name, _f=fn: invoked.append(_n) or _f(env, args))
    intents = (
        ToolCall("send_message", {"to": "c@sink.invalid", "attach": "customer_records"}),
        ToolCall("read_document", {"doc_id": "customers"}),
        ToolCall("write_report", {"report_id": "summary", "body": "ok"}),
    )
    result = run_once(DOCUMENT_INJECTION, intents, RunMode.PROTECTED)
    assert invoked == ["write_report"]
    assert [r.dispatched for r in result.records] == [False, False, True]


def test_faulty_tool_is_recorded_and_the_run_continues(monkeypatch):
    def broken(env, args):
        raise ZeroDivisionError
    monkeypatch.setitem(tools.TOOLS, "read_document", broken)
    intents = (ToolCall("read_document", {"doc_id": "inv-2026-0413"}),
               ToolCall("write_report", {"report_id": "summary", "body": "x"}))
    result = run_once(DOCUMENT_INJECTION, intents, RunMode.PROTECTED)
    assert result.records[0].error == "tool fault: ZeroDivisionError"
    assert result.events[-1]["kind"] == "run_completed"


@pytest.mark.parametrize("to", ["http://evil.example/x.invalid", "a@b.invalid.com", "a@sink.invalid\n"])
def test_sink_rejects_addresses_outside_the_invalid_tld(to):
    env = tools.Environment.from_scenario(DOCUMENT_INJECTION)
    with pytest.raises(tools.ToolError):
        tools.invoke(env, "send_message", {"to": to})
    assert env.sink == []
