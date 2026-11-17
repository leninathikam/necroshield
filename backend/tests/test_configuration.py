from fastapi.testclient import TestClient
from sqlalchemy import text

from necroshield.main import create_app


def test_configured_origin_is_explicit_and_unrelated_ports_remain_denied(tmp_path, monkeypatch):
    monkeypatch.setenv("NECROSHIELD_FRONTEND_ORIGIN", "http://127.0.0.1:4321")
    with TestClient(create_app(f"sqlite:///{tmp_path / 'arena.db'}")) as client:
        # Invalid scenario avoids spending a worker while proving origin pass-through.
        result = client.post("/api/runs", headers={"Origin": "http://127.0.0.1:4321"},
                             json={"scenario_id": "missing"})
        assert result.status_code == 404
        assert result.headers["access-control-allow-origin"] == "http://127.0.0.1:4321"
        blocked = client.post("/api/benchmarks", headers={"Origin": "http://127.0.0.1:4322"})
        assert blocked.status_code == 403


def test_health_fails_when_evidence_schema_is_unavailable_without_leaking_sql(tmp_path):
    with TestClient(create_app(f"sqlite:///{tmp_path / 'arena.db'}")) as client:
        assert client.get("/api/health").status_code == 200
        with client.app.state.repository.engine.begin() as connection:
            connection.execute(text("DROP TABLE run_pairs"))
        response = client.get("/api/health")
        assert response.status_code == 503
        assert response.json()["detail"] == "Evidence database unavailable; check migration and connection"
        assert "SELECT" not in response.text
