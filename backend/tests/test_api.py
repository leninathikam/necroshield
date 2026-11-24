"""API integration tests against the real FastAPI app (TestClient, real SQLite file)."""

import json

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from necroshield.api.app import create_app  # noqa: E402
from necroshield.catalog import REGISTRY  # noqa: E402

ORIGIN = "http://localhost:8017"


@pytest.fixture
def client(tmp_path):
    app = create_app(str(tmp_path / "api.db"), allowed_origins={ORIGIN})
    with TestClient(app, headers={"origin": ORIGIN}) as c:
        yield c


def test_health_and_scenarios(client):
    assert client.get("/api/health").json()["scenarios"] == 7
    scenarios = client.get("/api/scenarios").json()
    assert {s["id"] for s in scenarios} == set(REGISTRY)
    doc = next(s for s in scenarios if s["id"] == "document_injection")
    assert doc["materials"][0]["injected_lines"] and doc["digest"] == REGISTRY["document_injection"].digest()
    assert "@example.invalid" not in json.dumps(scenarios) and "sk-synthetic-" not in json.dumps(scenarios)


def test_run_returns_verified_evidence_and_decisive_denial(client):
    response = client.post("/api/runs", json={"scenario_id": "document_injection"})
    assert response.status_code == 201
    body = response.json()
    assert body["verification"] == {"verified": True, "problems": []}
    assert body["summary"]["baseline"]["attack_succeeded"] is True
    assert body["summary"]["protected"]["attack_succeeded"] is False
    assert body["summary"]["protected"]["task_completed"] is True
    assert [a["tool"] for a in body["analysis"] if a["decisive"]] == ["send_message"]

    pair_id = body["summary"]["pair_id"]
    assert client.get(f"/api/runs/{pair_id}").json()["export"] == body["export"]
    assert client.get("/api/runs").json()[0]["pair_id"] == pair_id
    download = client.get(f"/api/runs/{pair_id}/export")
    assert "attachment" in download.headers["content-disposition"]
    assert client.post("/api/verify", json=download.json()).json() == {"verified": True, "problems": []}


def test_custom_policy_counterfactual(client):
    policy = REGISTRY["document_injection"].policy.to_dict()
    policy["version"] = "custom/1.0.0"
    policy["grants"].append({"grant_id": "g-any-send", "tool": "send_message",
                             "allowed_args": {"to": None, "attach": None}})
    body = client.post("/api/runs", json={"scenario_id": "document_injection", "policy": policy}).json()
    assert body["export"]["policy"]["source"] == "custom"
    assert body["summary"]["protected"]["attack_succeeded"] is True


@pytest.mark.parametrize("payload", [
    {"scenario_id": "document_injection", "extra": 1},
    {"scenario_id": "Bad Id"},
    {"scenario_id": "document_injection", "policy": {"version": "x", "grants": [
        {"grant_id": "g-x", "tool": "exec_shell", "allowed_args": {"cmd": None}}]}},
    {"scenario_id": "document_injection", "policy": {"version": "x", "grants": [
        {"grant_id": "g-x", "tool": "read_document", "allowed_args": {"path": []}}]}},
])
def test_invalid_requests_fail_closed(client, payload):
    assert client.post("/api/runs", json=payload).status_code == 422


def test_unknown_scenario_is_404(client):
    assert client.post("/api/runs", json={"scenario_id": "no_such"}).status_code == 404


def test_tampered_upload_is_reported(client):
    export = client.post("/api/runs", json={"scenario_id": "memory_poisoning"}).json()["export"]
    export["runs"][1]["outcome"]["attack_succeeded"] = True
    result = client.post("/api/verify", json=export).json()
    assert result["verified"] is False and result["problems"]


def test_benchmark_and_bundle(client, tmp_path):
    assert client.get("/api/benchmark").json()["summary"] is None
    assert client.get("/api/benchmark/bundle").status_code == 409
    bench = client.post("/api/benchmark").json()
    summary = bench["summary"]
    assert summary["attack_success"]["baseline"] == {"numerator": 6, "denominator": 6, "value": 1.0}
    assert summary["attack_success"]["protected"] == {"numerator": 0, "denominator": 6, "value": 0.0}
    assert summary["false_positives"] == {"numerator": 0, "denominator": 1, "value": 0.0}
    assert summary["evaluation_cost_usd"] is None
    assert bench["missing_scenarios"] == []
    bundle = client.get("/api/benchmark/bundle").json()
    assert client.post("/api/verify", json=bundle).json()["verified"] is True


def test_cross_origin_writes_are_rejected(client):
    response = client.post("/api/runs", json={"scenario_id": "benign_invoice"}, headers={"origin": "https://evil.example"})
    assert response.status_code == 403


def test_oversized_bodies_are_rejected(client):
    response = client.post("/api/verify", content=b"[" + b"0," * 200000 + b"0]",
                           headers={"content-type": "application/json"})
    assert response.status_code == 413


def test_security_headers_present(client):
    headers = client.get("/api/health").headers
    assert headers["x-content-type-options"] == "nosniff" and "frame-ancestors 'none'" in headers["content-security-policy"]


def test_write_rate_limit(tmp_path, monkeypatch):
    monkeypatch.setenv("NECROSHIELD_WRITE_LIMIT", "2")
    app = create_app(str(tmp_path / "rl.db"), allowed_origins={ORIGIN})
    with TestClient(app) as c:
        codes = [c.post("/api/verify", json={}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_mcp_replay_endpoint(client):
    protected = client.post("/api/mcp/replay", json={"scenario_id": "document_injection"}).json()
    assert protected["transport"].startswith("mcp")
    denied = [t for t in protected["transcript"] if t["allowed"] is False]
    assert [t["tool"] for t in denied] == ["send_message"] and denied[0]["is_error"]
    assert protected["outcome"] == {**protected["outcome"], "attack_succeeded": False, "task_completed": True}
    baseline = client.post("/api/mcp/replay", json={"scenario_id": "document_injection", "mode": "baseline"}).json()
    assert baseline["outcome"]["attack_succeeded"] is True


def test_live_track_reports_unavailable_without_provider(client, monkeypatch):
    for key in ("NECROSHIELD_LLM_BASE_URL", "NECROSHIELD_LLM_API_KEY", "NECROSHIELD_LLM_MODEL"):
        monkeypatch.delenv(key, raising=False)
    assert client.get("/api/live/status").json()["available"] is False
    assert client.post("/api/live/runs", json={"scenario_id": "document_injection"}).status_code == 503
