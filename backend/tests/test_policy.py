import pytest
from hypothesis import given, settings, strategies as st

from necroshield.contracts import ToolCall
from necroshield.evidence import Trace
from necroshield.gateway import Gateway
from necroshield.policy import TrustedScope, authorize
from necroshield.scenarios import DOCUMENT_INJECTION
from necroshield.tools import SyntheticWorld


@given(st.text(min_size=1, max_size=80).filter(lambda value: value not in {"document.read", "report.write"}))
@settings(max_examples=100, deadline=None)
def test_unknown_or_ungranted_tools_are_default_denied(tool):
    decision = authorize(ToolCall(tool=tool, arguments={}), TrustedScope())
    assert decision.allowed is False


@given(st.text(max_size=200).filter(lambda value: value != "doc://invoice-001"))
@settings(max_examples=100, deadline=None)
def test_resource_scope_is_exact_and_cannot_be_traversed(document_id):
    decision = authorize(ToolCall(tool="document.read", arguments={"document_id": document_id}), TrustedScope())
    assert not decision.allowed


@pytest.mark.parametrize("tool,args", [
    ("sink.send", {"destination": "https://external.invalid", "payload": "synthetic"}),
    ("document.read", {"document_id": "doc://invoice-001", "role": "administrator"}),
    ("report.write", {"report_id": "report://summary", "text": "x" * 4001}),
    ("document.read", {"document_id": ["doc://invoice-001"]}),
    ("shell.exec", {"command": "echo inert"}),
])
def test_out_of_catalogue_and_invalid_arguments_never_reach_dispatcher(tool, args):
    world, trace = SyntheticWorld(DOCUMENT_INJECTION), Trace()
    result = Gateway(world, trace, protected=True).call(ToolCall(tool=tool, arguments=args))
    assert result["executed"] is False
    assert world.executed == []
    assert [event.kind for event in trace.events] == ["policy.decision"]


def test_a_malicious_directive_cannot_grant_itself_capabilities():
    call = ToolCall(tool="admin.grant", arguments={"principal": "target-agent", "role": "administrator"})
    assert not authorize(call, TrustedScope()).allowed
    assert not authorize(ToolCall(tool="document.read", arguments={"document_id": "doc://invoice-001"}),
                         TrustedScope(principal="administrator")).allowed
