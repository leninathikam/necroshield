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
    assert client.post("/api/live/runs", json={"scenario_id": "document_injection"}).status_code == 403


def test_streamed_oversized_bodies_are_rejected(client):
    def chunks():
        for _ in range(64):
            yield b" " * 8192
    response = client.post("/api/verify", content=chunks(), headers={"content-type": "application/json"})
    assert response.status_code == 413


def test_unverified_rows_do_not_break_listings(tmp_path):
    import sqlite3
    db = tmp_path / "bad.db"
    app = create_app(str(db), allowed_origins={ORIGIN})
    with TestClient(app, headers={"origin": ORIGIN}) as c:
        c.post("/api/runs", json={"scenario_id": "benign_invoice"})
        raw = sqlite3.connect(db)
        raw.execute("DROP TRIGGER pairs_no_update")
        raw.execute("UPDATE pairs SET export_json = '{}'")
        raw.commit()
        raw.close()
        rows = c.get("/api/runs").json()
        assert rows[0]["verified"] is False and rows[0]["protected"] is None
        assert c.get("/api/benchmark").status_code == 200


def test_bundle_upload_is_checked_against_current_definitions(client):
    client.post("/api/benchmark")
    bundle = client.get("/api/benchmark/bundle").json()
    bundle["pairs"] = bundle["pairs"][:3]
    result = client.post("/api/verify", json=bundle).json()
    assert result["verified"] is False


def test_pins_endpoint_matches_catalog(client):
    pins = client.get("/api/pins").json()
    assert pins["document_injection"]["scenario_digest"] == REGISTRY["document_injection"].digest()



def test_same_origin_writes_work_without_any_origin_configuration(tmp_path):
    app = create_app(str(tmp_path / "so.db"), allowed_origins=set())
    with TestClient(app, base_url="https://necroshield.example") as c:
        ok = c.post("/api/runs", json={"scenario_id": "benign_invoice"},
                    headers={"origin": "https://necroshield.example"})
        bad = c.post("/api/runs", json={"scenario_id": "benign_invoice"},
                     headers={"origin": "https://necroshield.example.evil.test"})
    assert ok.status_code == 201 and bad.status_code == 403


def test_render_external_url_is_an_allowed_origin(tmp_path, monkeypatch):
    monkeypatch.setenv("RENDER_EXTERNAL_URL", "https://necroshield.onrender.com")
    app = create_app(str(tmp_path / "r.db"))
    with TestClient(app) as c:
        response = c.post("/api/verify", json={}, headers={"origin": "https://necroshield.onrender.com"})
    assert response.status_code == 200


def test_proxy_hop_client_keys_cannot_be_forged(tmp_path, monkeypatch):
    monkeypatch.setenv("NECROSHIELD_PROXY_HOPS", "1")
    monkeypatch.setenv("NECROSHIELD_WRITE_LIMIT", "2")
    app = create_app(str(tmp_path / "p.db"), allowed_origins={ORIGIN})
    with TestClient(app) as c:
        key = lambda xff: c.get("/api/client-key", headers={"x-forwarded-for": xff}).json()["client_key_hash"]
        assert key("203.0.113.1") == key("1.1.1.1, 203.0.113.1") != key("203.0.113.2")
        codes = [c.post("/api/verify", json={}, headers={"x-forwarded-for": f"{i}.0.0.1, 203.0.113.9"}).status_code
                 for i in range(3)]
        assert codes == [200, 200, 429]
        assert c.post("/api/verify", json={}, headers={"x-forwarded-for": "203.0.113.10"}).status_code == 200


def test_benchmark_runs_have_their_own_tighter_limit(tmp_path, monkeypatch):
    monkeypatch.setenv("NECROSHIELD_BENCHMARK_LIMIT", "1")
    app = create_app(str(tmp_path / "b.db"), allowed_origins={ORIGIN})
    with TestClient(app) as c:
        assert [c.post("/api/benchmark").status_code for _ in range(2)] == [201, 429]
        assert c.post("/api/runs", json={"scenario_id": "benign_invoice"}).status_code == 201


def test_global_write_limit_bounds_total_load(tmp_path, monkeypatch):
    monkeypatch.setenv("NECROSHIELD_PROXY_HOPS", "1")
    monkeypatch.setenv("NECROSHIELD_GLOBAL_WRITE_LIMIT", "3")
    app = create_app(str(tmp_path / "g.db"), allowed_origins={ORIGIN})
    with TestClient(app) as c:
        codes = [c.post("/api/verify", json={}, headers={"x-forwarded-for": f"198.51.100.{i}"}).status_code for i in range(4)]
    assert codes == [200, 200, 200, 429]


def test_deeply_nested_json_is_a_client_error(client):
    body = b"[" * 100000 + b"]" * 100000
    response = client.post("/api/verify", content=body, headers={"content-type": "application/json"})
    assert response.status_code == 400
    assert client.get("/api/health").status_code == 200


def test_live_runs_need_the_operator_token_even_with_a_provider(tmp_path, monkeypatch):
    monkeypatch.setenv("NECROSHIELD_LLM_BASE_URL", "https://llm.test/v1")
    monkeypatch.setenv("NECROSHIELD_LLM_API_KEY", "sk-secret-provider-key")
    monkeypatch.setenv("NECROSHIELD_LLM_MODEL", "m")
    monkeypatch.setenv("NECROSHIELD_LLM_ALLOWED_HOSTS", "llm.test")
    app = create_app(str(tmp_path / "l.db"), allowed_origins={ORIGIN})
    with TestClient(app) as c:
        status = c.get("/api/live/status").json()
        assert status["available"] is False and status["configured"] is True
        assert "sk-secret-provider-key" not in json.dumps(status) and "https://llm.test/v1" not in json.dumps(status)
        assert c.post("/api/live/runs", json={"scenario_id": "document_injection"}).status_code == 403
    monkeypatch.setenv("NECROSHIELD_LIVE_OPERATOR_TOKEN", "t" * 40)
    app = create_app(str(tmp_path / "l2.db"), allowed_origins={ORIGIN})
    with TestClient(app) as c:
        wrong = c.post("/api/live/runs", json={"scenario_id": "document_injection"},
                       headers={"authorization": "Bearer " + "x" * 40})
        assert wrong.status_code == 401


def test_short_operator_tokens_leave_live_runs_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("NECROSHIELD_LIVE_OPERATOR_TOKEN", "short")
    app = create_app(str(tmp_path / "s.db"), allowed_origins={ORIGIN})
    with TestClient(app) as c:
        r = c.post("/api/live/runs", json={"scenario_id": "document_injection"}, headers={"authorization": "Bearer short"})
    assert r.status_code == 403


def test_seed_on_start_fills_the_benchmark_once(tmp_path, monkeypatch):
    monkeypatch.setenv("NECROSHIELD_SEED_ON_START", "1")
    db = str(tmp_path / "seed.db")
    with TestClient(create_app(db, allowed_origins={ORIGIN})) as c:
        assert c.get("/api/benchmark").json()["missing_scenarios"] == []
        first = c.get("/api/health").json()["stored_pairs"]
    with TestClient(create_app(db, allowed_origins={ORIGIN})) as c:
        assert c.get("/api/health").json()["stored_pairs"] == first == 7


def test_corpus_lists_the_fixed_split(client):
    rows = client.get("/api/corpus").json()
    assert len(rows) == 21 and sum(r["kind"] == "control" for r in rows) == 11
    assert {r["split"] for r in rows} == {"development", "held_out"}
    assert next(r for r in rows if r["id"] == "document_injection")["split"] == "development"


def test_evolution_endpoint_matches_the_core_and_is_bounded(client):
    from necroshield.optimizer import evolve
    body = client.get("/api/evolution").json()
    assert body["selected"] == "scoped_trace" == evolve(3)["selected"]
    assert client.get("/api/evolution?variants=99").status_code == 422
    assert client.get("/api/evolution?variants=-1").status_code == 422


def test_theatre_endpoint(client):
    t = client.get("/api/theatre/data_exfiltration").json()
    assert t["selected"] == "scoped_trace" and t["red_team"]["baseline_attack_succeeded"]
    assert client.get("/api/theatre/benign_invoice").status_code == 404
    assert client.get("/api/theatre/nope").status_code == 404


def test_approving_a_candidate_runs_it_as_a_verified_custom_policy(client):
    ok = client.post("/api/theatre/tool_response_injection/approve", json={"strategy": "scoped_trace"})
    assert ok.status_code == 201
    body = ok.json()
    assert body["verification"]["verified"] and body["export"]["policy"]["source"] == "custom"
    assert body["summary"]["protected"]["attack_succeeded"] is False and body["summary"]["protected"]["task_completed"]
    # A rejected candidate can still be run, and it visibly fails.
    bad = client.post("/api/theatre/tool_response_injection/approve", json={"strategy": "allow_all"}).json()
    assert bad["summary"]["protected"]["attack_succeeded"] is True and bad["verification"]["verified"]
    # Scenario defaults are untouched by approvals.
    assert REGISTRY["tool_response_injection"].policy.digest() == client.get("/api/pins").json()["tool_response_injection"]["policy_digest"]


@pytest.mark.parametrize("strategy, status", [("global_scoped", 404), ("nope", 404), ("Bad Name", 422), ("", 422)])
def test_approve_rejects_unknown_strategies(client, strategy, status):
    assert client.post("/api/theatre/document_injection/approve", json={"strategy": strategy}).status_code == status


def test_approve_is_rate_limited_like_other_writes(tmp_path, monkeypatch):
    monkeypatch.setenv("NECROSHIELD_WRITE_LIMIT", "2")
    app = create_app(str(tmp_path / "a.db"), allowed_origins={ORIGIN})
    with TestClient(app) as c:
        codes = [c.post("/api/theatre/document_injection/approve", json={"strategy": "scoped_trace"}).status_code for _ in range(3)]
    assert codes == [201, 201, 429]
