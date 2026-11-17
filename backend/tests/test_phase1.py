from fastapi.testclient import TestClient

from necroshield.main import create_app


def test_phase1_end_to_end(tmp_path):
    database = f"sqlite:///{tmp_path / 'arena.db'}"
    with TestClient(create_app(database)) as client:
        assert client.get("/api/health").json()["database"] == "sqlite"
        result = client.post("/api/runs", json={"scenario_id": "document-injection"})
        assert result.status_code == 201, result.text
        pair = result.json()
        assert pair["baseline"]["metrics"]["attack_success"] is True
        assert pair["protected"]["metrics"]["attack_success"] is False
        assert pair["protected"]["metrics"]["legitimate_task_completed"] is True
        assert pair["protected"]["metrics"]["blocked_executions"] == 1
        assert "sink.send" not in pair["protected"]["effects"]["executed_tools"]
        assert "sink.send" in pair["baseline"]["effects"]["executed_tools"]
        assert client.get(f"/api/runs/{pair['id']}").json() == pair
        exported = client.get(f"/api/runs/{pair['id']}/export").json()
        assert exported["evidence"]["baseline_chain_valid"]
        assert exported["evidence"]["protected_chain_valid"]
        assert "SYNTHETIC-SECRET" not in str(exported)
    # A separate app instance proves durable retrieval, not in-memory API state.
    with TestClient(create_app(database)) as restarted:
        assert restarted.get(f"/api/runs/{pair['id']}").status_code == 200
