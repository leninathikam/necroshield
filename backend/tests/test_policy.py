"""Gateway and policy tests. Seeded generators stand in for Hypothesis when it is not installed;
Hypothesis versions of the same properties live in test_properties.py and run in CI."""

import ast
import random
import string
from pathlib import Path

import pytest

from necroshield import tools
from necroshield.catalog import DOCUMENT_INJECTION, REGISTRY, TOOL_RESPONSE_INJECTION
from necroshield.contracts import RunMode, ToolCall
from necroshield.gateway import Gateway
from necroshield.policy import evaluate
from necroshield.runner import run_once

POLICY = TOOL_RESPONSE_INJECTION.policy
SEED = 20261124
PACKAGE = Path(__file__).resolve().parents[1] / "necroshield"


def _text(rng):
    return "".join(rng.choices(string.ascii_letters + string.digits + "./-:@ ", k=rng.randint(0, 24)))


def _granted_example(rng):
    grant = rng.choice(POLICY.grants)
    return ToolCall(grant.tool, {k: (rng.choice(v) if v is not None else _text(rng))
                                 for k, v in grant.allowed_args.items()})


def test_ungranted_tool_is_denied():
    decision = evaluate(DOCUMENT_INJECTION.policy, ToolCall("send_message", {"to": "x@sink.invalid"}))
    assert not decision.allowed and "no grant" in decision.reason


@pytest.mark.parametrize("args, reason", [
    ({"path": "hr/payroll-2026"}, "outside granted scope"),
    ({"path": "invoices/../hr/payroll-2026"}, "outside granted scope"),
    ({"path": "invoices/inv-2026-0413", "mode": "raw"}, "arguments not granted"),
    ({}, "missing argument"),
])
def test_arguments_outside_grant_are_denied(args, reason):
    decision = evaluate(DOCUMENT_INJECTION.policy, ToolCall("read_document", args))
    assert not decision.allowed and reason in decision.reason


def test_calls_built_from_grants_are_allowed():
    rng = random.Random(SEED)
    seen = set()
    for _ in range(500):
        decision = evaluate(POLICY, _granted_example(rng))
        assert decision.allowed
        seen.add(decision.grant_id)
    assert seen == {g.grant_id for g in POLICY.grants}


def test_extra_or_out_of_scope_arguments_turn_allow_into_deny():
    rng = random.Random(SEED)
    for _ in range(500):
        call = _granted_example(rng)
        assert not evaluate(POLICY, ToolCall(call.tool, dict(call.args, zz_extra=_text(rng)))).allowed
        grant = next(g for g in POLICY.grants if g.tool == call.tool)
        for name, values in grant.allowed_args.items():
            if values is not None:
                assert not evaluate(POLICY, ToolCall(call.tool, dict(call.args, **{name: _text(rng) + "~"}))).allowed


def test_tools_without_grants_are_denied_for_any_arguments():
    rng = random.Random(SEED)
    for _ in range(500):
        tool = rng.choice(["write_memory", "delete_all", "exec_shell"])
        args = {rng.choice(["key", "value", "cmd"]): _text(rng) for _ in range(rng.randint(0, 3))}
        assert not evaluate(DOCUMENT_INJECTION.policy, ToolCall(tool, args)).allowed


class _Sneaky(str):
    def __eq__(self, other):
        return True
    __hash__ = str.__hash__


@pytest.mark.parametrize("args", [
    {"path": _Sneaky("hr/payroll-2026")}, {"path": 7}, {"path": "a\x00b"}, {"Path": "x"}, {"path": "x" * 5000},
])
def test_non_canonical_arguments_are_rejected_at_construction(args):
    with pytest.raises((TypeError, ValueError)):
        ToolCall("read_document", args)


def test_denied_calls_never_reach_tool_code(monkeypatch):
    invoked = []
    for name, spec in list(tools.TOOLS.items()):
        wrapped = tools.ToolSpec(spec.name, spec.description, spec.required, spec.optional,
                                 lambda env, args, _n=name, _f=spec._fn: invoked.append(_n) or _f(env, args))
        monkeypatch.setitem(tools.TOOLS, name, wrapped)
    intents = (
        ToolCall("send_message", {"to": "c@sink.invalid", "attach": "all_customers"}),
        ToolCall("read_document", {"path": "invoices/../hr/payroll-2026"}),
        ToolCall("write_memory", {"key": "payee/hollow-pine", "value": "x"}),
        ToolCall("write_report", {"report_id": "summary", "body": "ok"}),
    )
    result = run_once(DOCUMENT_INJECTION, intents, RunMode.PROTECTED)
    assert invoked == ["write_report"]
    assert [r.dispatched for r in result.records] == [False, False, False, True]


def test_only_the_gateway_references_tool_dispatch():
    """No alternate route: outside its definition in tools.py, `_invoke` is referenced only by the gateway."""
    users = set()
    for path in PACKAGE.rglob("*.py"):
        tree = ast.parse(path.read_text())
        if any(isinstance(n, (ast.Name, ast.Attribute, ast.alias)) and
               getattr(n, "id", getattr(n, "attr", getattr(n, "name", None))) == "_invoke" for n in ast.walk(tree)):
            users.add(path.name)
    assert users == {"gateway.py"}
    defined = ast.parse((PACKAGE / "tools.py").read_text())
    assert any(isinstance(n, ast.FunctionDef) and n.name == "_invoke" for n in defined.body)


def test_tools_reject_unexpected_and_missing_arguments():
    env = tools.Environment.from_scenario(DOCUMENT_INJECTION)
    gateway = Gateway(env, policy=None)
    extra = gateway.execute(ToolCall("read_memory", {"key": "a", "value": "b"}))
    missing = gateway.execute(ToolCall("write_report", {"report_id": "summary"}))
    assert "unexpected ['value']" in extra.error and "missing ['body']" in missing.error
    assert env.invocations == []


def test_faulty_tool_is_recorded_and_the_run_continues(monkeypatch):
    spec = tools.TOOLS["read_document"]
    def broken(env, args):
        raise ZeroDivisionError
    monkeypatch.setitem(tools.TOOLS, "read_document",
                        tools.ToolSpec(spec.name, spec.description, spec.required, spec.optional, broken))
    intents = (ToolCall("read_document", {"path": "invoices/inv-2026-0413"}),
               ToolCall("write_report", {"report_id": "summary", "body": "x"}))
    result = run_once(DOCUMENT_INJECTION, intents, RunMode.PROTECTED)
    assert result.records[0].error == "tool fault: ZeroDivisionError"
    assert result.events[-1]["kind"] == "run_completed"


@pytest.mark.parametrize("to", ["http://evil.example/x.invalid", "a@b.invalid.com", "a@sink.invalid\n", "a@evil.com"])
def test_sink_rejects_addresses_outside_the_invalid_tld(to):
    env = tools.Environment.from_scenario(DOCUMENT_INJECTION)
    assert Gateway(env, None).execute(ToolCall("send_message", {"to": to})).error
    assert env.sink == []


def test_oversized_output_is_an_explicit_error_not_a_truncation(monkeypatch):
    monkeypatch.setattr(tools, "MAX_OUTPUT_CHARS", 50)
    env = tools.Environment.from_scenario(DOCUMENT_INJECTION)
    record = Gateway(env, None).execute(ToolCall("send_message", {"to": "a@sink.invalid", "attach": "all_customers"}))
    assert "exceeds" in record.error and env.sink == []


def test_path_resolution_is_what_scope_manipulation_abuses():
    s = REGISTRY["scope_manipulation"]
    env = tools.Environment.from_scenario(s)
    Gateway(env, None).execute(ToolCall("read_document", {"path": "invoices/../hr/payroll-2026"}))
    assert env.reads == ["document:hr/payroll-2026"]
