"""Local synthetic arena API. Bind to loopback; deploy behind authentication."""

import json
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from .contracts import Benchmark, CreateRun, RunPair
from .evidence import export_pair
from .http_boundary import LocalIngressBoundary, configured_origins
from .scenarios import SCENARIOS, scenario_infos
from .storage import Repository
from .workers import WorkerFailure, execute_pair_isolated

logger = logging.getLogger("necroshield")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate = False


def create_app(database_url: str | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.repository = Repository(database_url)
        yield
        app.state.repository.close()

    app = FastAPI(title="NecroShield synthetic arena", version="0.1.0", lifespan=lifespan)
    origins = configured_origins()
    app.add_middleware(CORSMiddleware, allow_origins=list(origins),
                       allow_methods=["GET", "POST"], allow_headers=["Content-Type"])
    app.add_middleware(LocalIngressBoundary, allowed_origins=origins)

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request: Request, exc: SQLAlchemyError):
        logger.error(json.dumps({"event": "database.unavailable", "error_type": type(exc).__name__}))
        return JSONResponse(status_code=503, content={"detail": "Evidence database unavailable; check migration and connection"})

    @app.exception_handler(WorkerFailure)
    async def worker_error(request: Request, exc: WorkerFailure):
        return JSONResponse(status_code=503, content={"detail": str(exc)})

    @app.middleware("http")
    async def trace_request(request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        logger.info(json.dumps({"event": "http.request", "method": request.method,
            "path": request.url.path, "status": response.status_code,
            "latency_ms": round((time.perf_counter() - start) * 1000, 3)}))
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/api/health")
    def health(request: Request):
        request.app.state.repository.ping()
        return {"status": "ok", "execution_kind": "synthetic_fixture", "version": "0.1.0",
                "database": request.app.state.repository.backend}

    @app.get("/api/scenarios")
    def scenarios():
        return scenario_infos()

    @app.post("/api/runs", response_model=RunPair, status_code=201)
    def create_run(body: CreateRun, request: Request):
        if body.scenario_id not in SCENARIOS:
            raise HTTPException(status_code=404, detail="Unknown scenario")
        pair = execute_pair_isolated(body.scenario_id)
        request.app.state.repository.save(pair)
        return pair

    @app.get("/api/runs", response_model=list[RunPair])
    def list_runs(request: Request, limit: int = Query(50, ge=1, le=100)):
        return request.app.state.repository.list(limit)

    def require_pair(pair_id: UUID, request: Request) -> RunPair:
        pair = request.app.state.repository.get(str(pair_id))
        if pair is None:
            raise HTTPException(status_code=404, detail="Run pair not found")
        return pair

    @app.get("/api/runs/{pair_id}", response_model=RunPair)
    def get_run(pair_id: UUID, request: Request):
        return require_pair(pair_id, request)

    @app.get("/api/runs/{pair_id}/export")
    def export_run(pair_id: UUID, request: Request):
        pair = require_pair(pair_id, request)
        return JSONResponse(export_pair(pair), headers={
            "Content-Disposition": f'attachment; filename="necroshield-{pair.id}.json"'})

    @app.post("/api/benchmarks", response_model=Benchmark, status_code=201)
    def benchmark(request: Request):
        return run_benchmark(request.app.state.repository)

    @app.get("/api/benchmarks", response_model=list[Benchmark])
    def benchmarks(request: Request):
        return request.app.state.repository.list_benchmarks()

    return app


def run_benchmark(repository: Repository) -> Benchmark:
    start = time.perf_counter()
    pairs = [execute_pair_isolated(scenario.info.id) for scenario in SCENARIOS.values()]
    attacks = [p for p in pairs if SCENARIOS[p.scenario_id].info.is_attack]
    controls = [p for p in pairs if not SCENARIOS[p.scenario_id].info.is_attack]
    legitimate_calls = sum(sum(e.kind == "policy.decision" and e.tool in {"document.read", "report.write"}
                               for e in p.protected.events) for p in pairs)
    benchmark = Benchmark(id=str(uuid4()), created_at=datetime.now(timezone.utc), total_scenarios=len(pairs),
        attack_scenarios=len(attacks), control_scenarios=len(controls),
        baseline_attack_success_rate=sum(p.baseline.metrics.attack_success for p in attacks) / len(attacks) if attacks else 0,
        protected_attack_success_rate=sum(p.protected.metrics.attack_success for p in attacks) / len(attacks) if attacks else 0,
        protected_task_completion_rate=sum(p.protected.metrics.legitimate_task_completed for p in pairs) / len(pairs),
        false_positive_rate=sum(p.protected.metrics.false_positives for p in pairs) / legitimate_calls if legitimate_calls else 0,
        blocked_executions=sum(p.protected.metrics.blocked_executions for p in pairs),
        latency_ms=round((time.perf_counter() - start) * 1000, 3), pair_ids=[p.id for p in pairs])
    repository.save_benchmark(benchmark, pairs)
    return benchmark


app = create_app()
