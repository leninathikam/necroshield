"""HTTP API and static frontend host.

Every security conclusion returned here comes from an export that the standalone verifier has
just checked; responses carry the verification problems next to the data.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .. import agent
from ..catalog import REGISTRY
from ..evidence import redact
from ..live import ProviderConfig, run_live
from ..mcp_server import replay_over_mcp
from ..metrics import BUNDLE_FORMAT, summarize
from ..runner import decisive_denials, run_pair
from ..scenarios import Policy, Scenario
from ..storage import RunStore, StoredPair
from ..tools import TOOLS
from ..verification import verify_export
from .guards import Guards, RateLimiter
from .schemas import LiveRunRequest, McpDemoRequest, PolicyIn, RunRequest

MAX_BODY = 256 * 1024


def _scenario(scenario_id: str) -> Scenario:
    scenario = REGISTRY.get(scenario_id)
    if scenario is None:
        raise HTTPException(404, f"unknown scenario: {scenario_id}")
    return scenario


def _policy(policy_in: PolicyIn | None) -> Policy | None:
    if policy_in is None:
        return None
    try:
        return policy_in.to_policy()
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, f"invalid policy: {exc}") from None


def _summary(stored: StoredPair) -> dict[str, Any]:
    export = stored.export
    runs = {r["mode"]: r for r in export["runs"]}
    return {
        "pair_id": export["pair_id"], "created_at": stored.created_at, "verified": stored.verified,
        "scenario_id": export["scenario"]["id"], "scenario_kind": export["scenario"]["kind"],
        "policy_source": export["policy"]["source"], "duration_ms": round(stored.duration_ms, 2),
        # Conclusions are withheld unless the evidence verified.
        "baseline": runs["baseline"]["outcome"] if stored.verified else None,
        "protected": runs["protected"]["outcome"] if stored.verified else None,
        "denied_calls": sum(not e["data"]["allowed"] for e in runs["protected"]["events"] if e["kind"] == "tool_call")
        if stored.verified else None,
    }


def _detail(stored: StoredPair) -> dict[str, Any]:
    return {"summary": _summary(stored), "verification": {"verified": stored.verified, "problems": stored.problems},
            "analysis": stored.analysis, "export": stored.export}


def _scenario_view(s: Scenario) -> dict[str, Any]:
    surfaces = {**{f"document:{k}": v for k, v in s.documents.items()},
                **{f"customer:{k}": v for k, v in s.customer_records.items()}}
    return redact({
        "id": s.scenario_id, "version": s.version, "kind": s.kind, "title": s.title,
        "attack_class": s.attack_class, "trusted_task": s.trusted_task, "attacker_surface": s.attacker_surface,
        "forbidden_behavior": s.forbidden_behavior, "digest": s.digest(),
        "policy": {"digest": s.policy.digest(), **s.policy.to_dict()}, "allowed_tools": list(s.allowed_tools),
        "attack_checks": [c.to_dict() for c in s.attack_checks], "task_checks": [c.to_dict() for c in s.task_checks],
        "materials": [{"resource": k, "text": v,
                       "injected_lines": [m.group(0) for m in agent.INJECTED_CALL.finditer(v)]}
                      for k, v in surfaces.items()],
        "memory": dict(s.memory),
        "planned_intents": [c.to_dict() for c in agent.plan(s)],
    })


def create_app(db_path: str | None = None, static_dir: str | None = None,
               allowed_origins: set[str] | None = None) -> FastAPI:
    db_path = db_path or os.environ.get("NECROSHIELD_DB", "necroshield.db")
    origins = allowed_origins if allowed_origins is not None else {
        o.strip() for o in os.environ.get("NECROSHIELD_ALLOWED_ORIGINS", "http://localhost:8017").split(",") if o.strip()}
    store = RunStore(db_path)
    app = FastAPI(title="NecroShield", version="0.2.0", docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.state.store = store
    app.add_middleware(Guards, allowed_origins=origins, max_body=MAX_BODY,
                       limiter=RateLimiter({"write": int(os.environ.get("NECROSHIELD_WRITE_LIMIT", "60")),
                                            "live": int(os.environ.get("NECROSHIELD_LIVE_LIMIT", "3"))}))

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "scenarios": len(REGISTRY), "stored_pairs": store.count()}

    @app.get("/api/tools")
    def tools() -> list[dict[str, Any]]:
        return [{"name": s.name, "description": s.description, "required": list(s.required),
                 "optional": list(s.optional)} for s in TOOLS.values()]

    @app.get("/api/scenarios")
    def scenarios() -> list[dict[str, Any]]:
        return [_scenario_view(s) for s in REGISTRY.values()]

    @app.get("/api/scenarios/{scenario_id}")
    def scenario(scenario_id: str) -> dict[str, Any]:
        return _scenario_view(_scenario(scenario_id))

    @app.post("/api/runs", status_code=201)
    def create_run(request: RunRequest) -> dict[str, Any]:
        pair = run_pair(_scenario(request.scenario_id), _policy(request.policy))
        store.save(pair, decisive_denials(pair))
        return _detail(store.load(pair.pair_id))

    @app.get("/api/runs")
    def list_runs(limit: int = Query(25, ge=1, le=200)) -> list[dict[str, Any]]:
        return [_summary(p) for p in store.recent(limit)]

    @app.get("/api/runs/{pair_id}")
    def get_run(pair_id: str) -> dict[str, Any]:
        try:
            return _detail(store.load(pair_id))
        except KeyError:
            raise HTTPException(404, "unknown pair") from None

    @app.get("/api/runs/{pair_id}/export")
    def export_run(pair_id: str) -> JSONResponse:
        try:
            stored = store.load(pair_id)
        except KeyError:
            raise HTTPException(404, "unknown pair") from None
        return JSONResponse(stored.export, headers={
            "content-disposition": f'attachment; filename="necroshield-{pair_id}.json"'})

    @app.post("/api/verify")
    def verify(export: Any = Body(...)) -> dict[str, Any]:
        problems = verify_export(export)
        return {"verified": not problems, "problems": problems}

    def _benchmark() -> dict[str, Any]:
        population = store.latest_default_per_scenario()
        verified = [p for p in population if p.verified]
        exports = [p.export for p in verified]
        return {
            "summary": summarize(exports) if exports else None,
            "rows": [_summary(p) for p in population],
            "unverified_excluded": [p.export.get("pair_id") for p in population if not p.verified],
            "mean_pair_latency_ms": round(sum(p.duration_ms for p in verified) / len(verified), 3) if verified else None,
            "latency_note": "local in-process execution time; not part of the hash-chained evidence",
            "missing_scenarios": sorted(set(REGISTRY) - {p.export["scenario"]["id"] for p in population}),
        }

    @app.get("/api/benchmark")
    def benchmark() -> dict[str, Any]:
        return _benchmark()

    @app.post("/api/benchmark", status_code=201)
    def run_benchmark() -> dict[str, Any]:
        for scenario_obj in REGISTRY.values():
            pair = run_pair(scenario_obj)
            store.save(pair, decisive_denials(pair))
        return _benchmark()

    @app.get("/api/benchmark/bundle")
    def bundle() -> JSONResponse:
        verified = [p for p in store.latest_default_per_scenario() if p.verified]
        if not verified:
            raise HTTPException(409, "no verified benchmark runs yet")
        exports = [p.export for p in verified]
        body = {"format": BUNDLE_FORMAT, "summary": summarize(exports), "pairs": exports}
        return JSONResponse(body, headers={"content-disposition": 'attachment; filename="necroshield-benchmark.json"'})

    @app.post("/api/mcp/replay")
    async def mcp_replay(request: McpDemoRequest) -> dict[str, Any]:
        return await replay_over_mcp(_scenario(request.scenario_id), request.mode == "protected")

    @app.get("/api/live/status")
    def live_status() -> dict[str, Any]:
        try:
            config = ProviderConfig.from_env()
        except ValueError as exc:
            return {"available": False, "reason": str(exc)}
        if config is None:
            return {"available": False, "reason": "no model provider is configured on this server"}
        return {"available": True, **config.describe()}

    @app.post("/api/live/runs")
    async def live_runs(request: LiveRunRequest) -> dict[str, Any]:
        try:
            config = ProviderConfig.from_env()
        except ValueError as exc:
            raise HTTPException(503, str(exc)) from None
        if config is None:
            raise HTTPException(503, "live evaluation unavailable: no model provider is configured")
        scenario_obj = _scenario(request.scenario_id)
        runs = [await asyncio.to_thread(run_live, scenario_obj, config, request.mode == "protected",
                                        request.temperature) for _ in range(request.repetitions)]
        return {"evaluation_mode": "live_agent_evaluation", "repetitions": request.repetitions, "runs": runs}

    static = Path(static_dir or os.environ.get("NECROSHIELD_STATIC", "")) if (static_dir or os.environ.get("NECROSHIELD_STATIC")) else None
    if static and static.is_dir():
        app.mount("/", StaticFiles(directory=static, html=True), name="frontend")
    return app


def app_from_env() -> FastAPI:
    return create_app()
