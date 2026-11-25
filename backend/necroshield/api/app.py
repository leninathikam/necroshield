"""HTTP API and static frontend host.

Stored pair results are re-verified with the standalone verifier on every read, and responses
carry the verification problems next to the data; outcomes are withheld for unverified pairs.
MCP replay transcripts and live runs are labeled with their own, weaker evidence status.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import os
import threading
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, Header, HTTPException, Query, Request
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
from ..storage import RunStore, StorageFull, StoredPair
from ..tools import TOOLS
from ..verification import verify_export
from .guards import Guards, RateLimiter
from .schemas import LiveRunRequest, McpDemoRequest, PolicyIn, RunRequest

MAX_BODY = 256 * 1024
MIN_OPERATOR_TOKEN = 32
log = logging.getLogger("necroshield")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _origins_from_env() -> set[str]:
    origins = {o.strip().rstrip("/") for o in os.environ.get(
        "NECROSHIELD_ALLOWED_ORIGINS", "http://localhost:8017,http://localhost:3017").split(",") if o.strip()}
    external = os.environ.get("RENDER_EXTERNAL_URL", "").strip().rstrip("/")  # set by Render for web services
    if external:
        origins.add(external)
    return origins


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
    if not stored.verified:
        # Nothing from an unverified export is trusted, including its shape.
        return {"pair_id": str(export.get("pair_id", "")), "created_at": stored.created_at, "verified": False,
                "scenario_id": None, "scenario_kind": None, "policy_source": None,
                "duration_ms": round(stored.duration_ms, 2), "baseline": None, "protected": None, "denied_calls": None}
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
            "analysis": stored.analysis if stored.verified else [], "export": stored.export}


def _current_pins() -> dict[str, dict[str, str]]:
    return {s.scenario_id: {"scenario_digest": s.digest(), "policy_digest": s.policy.digest()} for s in REGISTRY.values()}


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
    origins = allowed_origins if allowed_origins is not None else _origins_from_env()
    store = RunStore(db_path, max_pairs=_env_int("NECROSHIELD_MAX_PAIRS", 5000))
    # Swagger UI loads assets from a CDN, which the CSP forbids; the OpenAPI document stays available.
    app = FastAPI(title="NecroShield", version="0.2.0", docs_url=None, redoc_url=None, openapi_url="/api/openapi.json")
    app.state.store = store
    app.add_middleware(
        Guards, allowed_origins=origins, max_body=MAX_BODY,
        proxy_hops=_env_int("NECROSHIELD_PROXY_HOPS", 0),
        client_ip_header=os.environ.get("NECROSHIELD_CLIENT_IP_HEADER") or None,
        limiter=RateLimiter({
            "write": _env_int("NECROSHIELD_WRITE_LIMIT", 60),
            "benchmark": _env_int("NECROSHIELD_BENCHMARK_LIMIT", 6),
            "global_write": _env_int("NECROSHIELD_GLOBAL_WRITE_LIMIT", 600),
            "live": _env_int("NECROSHIELD_LIVE_LIMIT", 3),
            "read": _env_int("NECROSHIELD_READ_LIMIT", 600),
        }))

    @app.exception_handler(RecursionError)
    async def too_deep(_request: Request, _exc: RecursionError) -> JSONResponse:
        return JSONResponse({"detail": "document is nested too deeply"}, status_code=400)
    scenario_views = [_scenario_view(s) for s in REGISTRY.values()]  # immutable definitions: build once
    live_budget = {"remaining": _env_int("NECROSHIELD_LIVE_MAX_RUNS", 30)}
    live_lock = threading.Lock()
    operator_token = os.environ.get("NECROSHIELD_LIVE_OPERATOR_TOKEN", "")
    if operator_token and len(operator_token) < MIN_OPERATOR_TOKEN:
        log.warning("NECROSHIELD_LIVE_OPERATOR_TOKEN is shorter than %d characters; live runs stay disabled",
                    MIN_OPERATOR_TOKEN)
        operator_token = ""

    def _save(pair: Any) -> None:
        try:
            store.save(pair, decisive_denials(pair))
        except StorageFull as exc:
            raise HTTPException(507, str(exc)) from None

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "scenarios": len(REGISTRY), "stored_pairs": store.count(), "max_pairs": store.max_pairs}

    @app.get("/api/client-key")
    def client_key(request: Request) -> dict[str, str]:
        """A hash of the key this request was rate limited under. Lets an operator confirm, after
        deploying behind a proxy, that different clients get different keys and that sending a
        forged X-Forwarded-For does not change yours."""
        return {"client_key_hash": getattr(request.state, "client_key_hash", "")}

    @app.get("/api/tools")
    def tools() -> list[dict[str, Any]]:
        return [{"name": s.name, "description": s.description, "required": list(s.required),
                 "optional": list(s.optional)} for s in TOOLS.values()]

    @app.get("/api/scenarios")
    def scenarios() -> list[dict[str, Any]]:
        return scenario_views

    @app.get("/api/scenarios/{scenario_id}")
    def scenario(scenario_id: str) -> dict[str, Any]:
        _scenario(scenario_id)
        return next(v for v in scenario_views if v["id"] == scenario_id)

    @app.get("/api/pins")
    def pins() -> dict[str, dict[str, str]]:
        return _current_pins()

    @app.post("/api/runs", status_code=201)
    def create_run(request: RunRequest) -> dict[str, Any]:
        pair = run_pair(_scenario(request.scenario_id), _policy(request.policy))
        _save(pair)
        return _detail(store.load(pair.pair_id))

    @app.get("/api/runs")
    def list_runs(limit: int = Query(25, ge=1, le=100)) -> list[dict[str, Any]]:
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
        # Bundles are checked against this server's current definitions, which also fixes the
        # expected scenario set; single pairs may use custom policies, so they are not pinned.
        is_bundle = isinstance(export, dict) and export.get("format") == BUNDLE_FORMAT
        problems = verify_export(export, pins=_current_pins() if is_bundle else None)
        return {"verified": not problems, "problems": problems}

    def _benchmark() -> dict[str, Any]:
        current = {s.scenario_id: (s.digest(), s.policy.digest()) for s in REGISTRY.values()}
        population = store.latest_default_per_scenario(current)
        verified = [p for p in population if p.verified]
        exports = [p.export for p in verified]
        return {
            "summary": summarize(exports) if exports else None,
            "rows": [_summary(p) for p in population],
            "unverified_excluded": [p.export.get("pair_id") for p in population if not p.verified],
            "mean_pair_latency_ms": round(sum(p.duration_ms for p in verified) / len(verified), 3) if verified else None,
            "latency_note": "local in-process execution time; not part of the hash-chained evidence",
            "missing_scenarios": sorted(set(REGISTRY) - {p.export["scenario"]["id"] for p in verified}),
        }

    @app.get("/api/benchmark")
    def benchmark() -> dict[str, Any]:
        return _benchmark()

    @app.post("/api/benchmark", status_code=201)
    def run_benchmark() -> dict[str, Any]:
        for scenario_obj in REGISTRY.values():
            _save(run_pair(scenario_obj))
        return _benchmark()

    @app.get("/api/benchmark/bundle")
    def bundle() -> JSONResponse:
        current = {s.scenario_id: (s.digest(), s.policy.digest()) for s in REGISTRY.values()}
        verified = [p for p in store.latest_default_per_scenario(current) if p.verified]
        if not verified:
            raise HTTPException(409, "no verified benchmark runs yet")
        exports = [p.export for p in verified]
        body = {"format": BUNDLE_FORMAT, "summary": summarize(exports), "pairs": exports}
        return JSONResponse(body, headers={"content-disposition": 'attachment; filename="necroshield-benchmark.json"'})

    @app.post("/api/mcp/replay")
    async def mcp_replay(request: McpDemoRequest) -> dict[str, Any]:
        result = await replay_over_mcp(_scenario(request.scenario_id), request.mode == "protected")
        result["evidence"] = "transcript only: not hash-chained, not stored, and not verified"
        return result

    @app.get("/api/live/status")
    def live_status() -> dict[str, Any]:
        """`available` means a visitor's browser can start a live run, which is never the case:
        paid inference is operator-only (CLI, or the API with the operator token)."""
        try:
            config = ProviderConfig.from_env()
        except ValueError as exc:
            return {"available": False, "configured": False, "reason": str(exc)}
        if config is None:
            return {"available": False, "configured": False, "reason": "no model provider is configured on this server"}
        return {"available": False, "configured": True, "operator_api_enabled": bool(operator_token),
                "reason": "live model runs are operator-only on this server", **config.describe()}

    @app.post("/api/live/runs")
    async def live_runs(request: LiveRunRequest, authorization: str = Header(default="")) -> dict[str, Any]:
        if not operator_token:
            raise HTTPException(403, "live runs are disabled on this server (no operator token configured)")
        supplied = authorization.removeprefix("Bearer ").strip()
        if not hmac.compare_digest(supplied.encode(), operator_token.encode()):
            raise HTTPException(401, "live runs require the operator token")
        try:
            config = ProviderConfig.from_env()
        except ValueError as exc:
            raise HTTPException(503, str(exc)) from None
        if config is None:
            raise HTTPException(503, "live evaluation unavailable: no model provider is configured")
        scenario_obj = _scenario(request.scenario_id)
        if not live_lock.acquire(blocking=False):
            raise HTTPException(429, "a live evaluation is already running")
        try:
            if live_budget["remaining"] < request.repetitions:
                raise HTTPException(429, "live evaluation budget for this server process is exhausted")
            live_budget["remaining"] -= request.repetitions
            runs = [await asyncio.to_thread(run_live, scenario_obj, config, request.mode == "protected",
                                            request.temperature) for _ in range(request.repetitions)]
        finally:
            live_lock.release()
        for run in runs:
            run["verification"] = verify_export(run)
        return {"evaluation_mode": "live_agent_evaluation", "repetitions": request.repetitions, "runs": runs,
                "note": "each run is a separate model execution; runs are not paired or merged into fixture metrics"}

    if os.environ.get("NECROSHIELD_SEED_ON_START") == "1":
        # Judges should never land on an empty benchmark, including after a restart on ephemeral disk.
        if _benchmark()["missing_scenarios"]:
            for scenario_obj in REGISTRY.values():
                _save(run_pair(scenario_obj))
            log.info("seeded the benchmark with one verified pair per scenario")

    static = Path(static_dir or os.environ.get("NECROSHIELD_STATIC", "")) if (static_dir or os.environ.get("NECROSHIELD_STATIC")) else None
    if static and static.is_dir():
        app.mount("/", StaticFiles(directory=static, html=True), name="frontend")
    return app


def app_from_env() -> FastAPI:
    return create_app()
