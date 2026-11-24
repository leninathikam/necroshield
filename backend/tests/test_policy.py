import random
import string

import pytest

from necroshield import tools
from necroshield.contracts import RunMode, ToolCall
from necroshield.policy import evaluate
from necroshield.runner import run_once
from necroshield.scenarios import DOCUMENT_INJECTION

POLICY = DOCUMENT_INJECTION.policy


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


def test_matching_call_records_grant_id():
    decision = evaluate(POLICY, ToolCall("read_document", {"doc_id": "inv-2026-0413"}))
    assert decision.allowed and decision.grant_id == "g-read-invoice"


def _random_call(rng: random.Random) -> ToolCall:
    tool = rng.choice(["read_document", "write_report", "send_message", "delete_all", "read_memory"])
    keys = rng.sample(["doc_id", "report_id", "body", "to", "attach", "path"], k=rng.randint(0, 3))
    pool = ["inv-2026-0413", "summary", "customers", "", *("".join(rng.choices(string.printable, k=8)),)]
    return ToolCall(tool, {k: rng.choice(pool) for k in keys})


def _covered(call: ToolCall) -> bool:
    for grant in POLICY.grants:
        if grant.tool != call.tool or set(call.args) != set(grant.allowed_args):
            continue
        if all(v is None or call.args[k] in v for k, v in grant.allowed_args.items()):
            return True
    return False


def test_seeded_random_calls_are_allowed_only_when_a_grant_covers_them():
    # Seeded generative check standing in for Hypothesis until it can be installed.
    rng = random.Random(20261124)
    for _ in range(2000):
        call = _random_call(rng)
        assert evaluate(POLICY, call).allowed == _covered(call), call


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
