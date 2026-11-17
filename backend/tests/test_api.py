from uuid import uuid4

from fastapi.testclient import TestClient

from necroshield.main import create_app


def test_validation_and_missing_evidence(tmp_path):
    with TestClient(create_app(f"sqlite:///{tmp_path / 'arena.db'}")) as client:
        assert len(client.get("/api/scenarios").json()) == 7
        assert client.post("/api/runs", json={"scenario_id": "not-a-scenario"}).status_code == 404
        assert client.post("/api/runs", json={"scenario_id": "../../file"}).status_code == 422
        assert client.post("/api/runs", json={"scenario_id": "document-injection", "payload": "inert"}).status_code == 422
        assert client.get("/api/runs/not-a-uuid").status_code == 422
        assert client.get(f"/api/runs/{uuid4()}").status_code == 404
        assert client.get("/api/runs?limit=1000").status_code == 422
        assert client.get("/api/runs").json() == []


def test_full_benchmark_runs_isolated_workers_and_persists_atomic_group(tmp_path):
    with TestClient(create_app(f"sqlite:///{tmp_path / 'arena.db'}")) as client:
        response = client.post("/api/benchmarks")
        assert response.status_code == 201, response.text
        benchmark = response.json()
        assert benchmark["total_scenarios"] == 7
        assert benchmark["attack_scenarios"] == 6
        assert benchmark["control_scenarios"] == 1
        assert benchmark["baseline_attack_success_rate"] == 1
        assert benchmark["protected_attack_success_rate"] == 0
        assert benchmark["protected_task_completion_rate"] == 1
        assert benchmark["false_positive_rate"] == 0
        assert benchmark["blocked_executions"] == 6
        assert benchmark["cost_usd"] is None
        assert len(client.get("/api/runs").json()) == 7
        assert client.get("/api/benchmarks").json() == [benchmark]
        for identifier in benchmark["pair_ids"]:
            assert client.get(f"/api/runs/{identifier}/export").json()["evidence"]["protected_chain_valid"]
