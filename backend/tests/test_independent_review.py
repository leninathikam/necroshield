"""Independent regressions for browser-origin and pre-parse API boundaries."""

import json

import pytest
from fastapi.testclient import TestClient

from necroshield.contracts import ToolCall
from necroshield.engine import build_intent_tape, execute_pair
from necroshield.evidence import Trace
from necroshield.gateway import Gateway
from necroshield.main import create_app
from necroshield.scenarios import DOCUMENT_INJECTION
from necroshield.tools import SyntheticWorld


def test_planning_materializes_fixture_without_untraced_tool_dispatch(monkeypatch):
    def no_dispatch(_self, _call):
        raise AssertionError("Intent planning executed an untraced tool")

    monkeypatch.setattr(SyntheticWorld, "execute", no_dispatch)
    tape = build_intent_tape(DOCUMENT_INJECTION)
    assert tape[0].tool == "document.read"
    assert tape[-1].tool == "report.write"


@pytest.mark.parametrize("key", ["access_token", "refresh_token", "client_secret", "apiKey",
                                 "passwd", "private_key", "credentials", "cookie"])
def test_denied_call_evidence_redacts_credential_aliases_recursively(key):
    world, trace = SyntheticWorld(DOCUMENT_INJECTION), Trace()
    credential = "fixture-private-value-do-not-export"
    result = Gateway(world, trace, protected=True).call(ToolCall(tool="document.read", arguments={
        "document_id": "doc://invoice-001", key: credential,
        "metadata": {"outer": [{key: credential}]},
    }))
    assert result["executed"] is False
    assert world.executed == []
    assert credential not in str([event.model_dump() for event in trace.events])
    assert trace.events[0].arguments[key] == "[REDACTED]"
    assert trace.events[0].arguments["metadata"]["outer"][0][key] == "[REDACTED]"


@pytest.fixture
def client(tmp_path, monkeypatch):
    def never_execute(_scenario_id):
        raise AssertionError("Rejected input reached the fixture executor")

    monkeypatch.setattr("necroshield.main.execute_pair_isolated", never_execute)
    with TestClient(create_app(f"sqlite:///{tmp_path / 'review.db'}")) as instance:
        yield instance


@pytest.mark.parametrize("origin", ["https://hostile.invalid", "null", "http://127.0.0.1:9000", "http://127.0.0.1:3000"])
def test_cross_origin_simple_post_cannot_execute_benchmark(client, origin):
    # A browser can send this simple POST without a CORS preflight. Merely
    # withholding Access-Control-Allow-Origin would not prevent its side effect.
    response = client.post("/api/benchmarks", headers={"Origin": origin})
    assert response.status_code == 403
    assert client.get("/api/benchmarks").json() == []


def test_cross_origin_json_request_cannot_execute_run(client):
    response = client.post("/api/runs", json={"scenario_id": "document-injection"},
                           headers={"Origin": "https://hostile.invalid"})
    assert response.status_code == 403


def test_oversized_content_length_rejected_before_execution(client):
    response = client.post("/api/runs", content=b"{}", headers={
        "Content-Type": "application/json", "Content-Length": "5000"})
    assert response.status_code == 413


def test_chunked_oversized_body_rejected_before_json_validation(client):
    encoded = json.dumps({"scenario_id": "document-injection", "padding": "x" * 5000}).encode()
    response = client.post("/api/runs", content=iter([encoded[:2500], encoded[2500:]]),
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 413


@pytest.mark.parametrize("origin", [None, "http://127.0.0.1:3017", "http://localhost:3017"])
def test_local_dashboard_and_originless_cli_still_execute(client, monkeypatch, origin):
    calls = []

    def fixed_fixture(scenario_id):
        calls.append(scenario_id)
        return execute_pair(DOCUMENT_INJECTION)

    monkeypatch.setattr("necroshield.main.execute_pair_isolated", fixed_fixture)
    response = client.post("/api/runs", json={"scenario_id": "document-injection"},
                           headers={"Origin": origin} if origin else {})
    assert response.status_code == 201, response.text
    assert calls == ["document-injection"]
    assert response.json()["protected"]["metrics"]["attack_success"] is False
