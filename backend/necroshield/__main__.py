"""CLI.

  python -m necroshield scenarios                      list scenarios and the digests to pin
  python -m necroshield run SCENARIO [--db PATH] [--export FILE]
  python -m necroshield benchmark [--db PATH]          run every scenario once and print the table
  python -m necroshield reset-store --db PATH --yes    delete all stored runs (demo reset)
  python -m necroshield live --out DIR [...]           operator-only live-model experiment (paid; budgeted)
"""

from __future__ import annotations

import argparse
import json
import sys

from .runner import decisive_denials, run_pair
from .catalog import REGISTRY, get_scenario
from .storage import RunStore


def _list_scenarios(as_pins: bool) -> None:
    if as_pins:
        print(json.dumps({s.scenario_id: {"scenario_digest": s.digest(), "policy_digest": s.policy.digest()}
                          for s in REGISTRY.values()}, indent=2))
        return
    for s in REGISTRY.values():
        print(f"{s.scenario_id}@{s.version} ({s.kind})")
        print(f"  scenario digest {s.digest()}")
        print(f"  policy {s.policy.version} digest {s.policy.digest()}")


def _run(scenario_id: str, db: str, export_path: str | None) -> None:
    # Claim the export file before running, so a refused export never leaves a half-recorded pair.
    handle = open(export_path, "x", encoding="utf-8") if export_path else None
    try:
        _run_into(scenario_id, db, export_path, handle)
    finally:
        if handle:
            handle.close()


def _run_into(scenario_id: str, db: str, export_path: str | None, handle) -> None:
    pair = run_pair(get_scenario(scenario_id))
    store = RunStore(db)
    try:
        store.save(pair)
    finally:
        store.close()

    print(f"pair {pair.pair_id}  scenario {pair.scenario.scenario_id}@{pair.scenario.version}  "
          f"replay deterministic_intent_replay")
    for run in (pair.baseline, pair.protected):
        denied = sum(not r.decision.allowed for r in run.records)
        print(f"  {run.mode.value:9} attack_succeeded={run.outcome.attack_succeeded!s:5} "
              f"task_completed={run.outcome.task_completed!s:5} denied={denied} run {run.run_id}")
    if handle:
        json.dump(pair.export(), handle, indent=2)
        print(f"  export written to {export_path}")


def _benchmark(db: str) -> None:
    store = RunStore(db)
    try:
        print(f"{'scenario':28} {'kind':8} {'baseline':18} {'protected':18} denied  decisive")
        for scenario in REGISTRY.values():
            pair = run_pair(scenario)
            store.save(pair)
            cells = [f"atk={r.outcome.attack_succeeded!s:5} task={r.outcome.task_completed!s:5}"
                     for r in (pair.baseline, pair.protected)]
            denied = sum(not r.decision.allowed for r in pair.protected.records)
            decisive = sum(d["decisive"] for d in decisive_denials(pair))
            print(f"{scenario.scenario_id:28} {scenario.kind:8} {cells[0]:18} {cells[1]:18} {denied:<7} {decisive}")
    finally:
        store.close()


def _reset(db: str) -> None:
    store = RunStore(db)
    try:
        print(f"removed {store.reset()} stored pairs from {db}")
    finally:
        store.close()


def _live(args: argparse.Namespace) -> int:
    """Runs on the operator's machine or server shell only; never reachable from the web UI."""
    from pathlib import Path

    from .budget import BudgetExceeded, Ledger
    from .live import ProviderConfig, run_live
    from .verification import verify_export

    config = ProviderConfig.from_env()
    if config is None:
        print("live evaluation unavailable: set NECROSHIELD_LLM_BASE_URL, _API_KEY, _MODEL, _ALLOWED_HOSTS", file=sys.stderr)
        return 2
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    ledger = Ledger(Path(args.ledger), args.budget_usd)
    scenarios = sorted(REGISTRY) if args.scenarios == "all" else args.scenarios.split(",")
    modes = args.modes.split(",")
    results = []
    try:
        for scenario_id in scenarios:
            for mode in modes:
                for rep in range(args.repetitions):
                    worst = ledger.reserve(config)
                    run = run_live(get_scenario(scenario_id), config, protected=mode == "protected",
                                   temperature=args.temperature)
                    problems = verify_export(run)
                    charged = ledger.record(run)
                    (out / f"{scenario_id}-{mode}-{rep}-{run['run_id'][:8]}.json").write_text(json.dumps(run, indent=2))
                    o = run["outcome"]
                    results.append({"scenario": scenario_id, "mode": mode, "repetition": rep, "run_id": run["run_id"],
                                    "attack_succeeded": o["attack_succeeded"], "task_completed": o["task_completed"],
                                    "failure": o["failure"], "usage": run["usage"], "estimated_cost_usd": run["cost_usd"],
                                    "provider_reported_cost_usd": run["provider_reported_cost_usd"],
                                    "verified": not problems})
                    print(f"{scenario_id:28} {mode:9} rep {rep}  attack={o['attack_succeeded']!s:5} "
                          f"task={o['task_completed']!s:5} failure={o['failure'] or '-'}  charged=${charged:.5f} "
                          f"(reserved ${worst:.4f})  verified={not problems}")
    except BudgetExceeded as exc:
        print(f"stopped: {exc}", file=sys.stderr)
    summary = {
        "evaluation_mode": "live_agent_evaluation", "provider": config.describe(), "temperature": args.temperature,
        "note": "separate from deterministic_intent_replay; runs are independent model executions",
        "runs": results, "ledger_spent_usd": ledger.spent, "budget_usd": args.budget_usd,
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"{len(results)} runs; ledger spent ${ledger.spent:.4f} of ${args.budget_usd:.2f}; summary in {out / 'summary.json'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="necroshield")
    sub = parser.add_subparsers(dest="command", required=True)
    listing = sub.add_parser("scenarios", help="list scenarios and their digests")
    listing.add_argument("--pins", action="store_true", help="print a pins file for the standalone verifier")
    bench = sub.add_parser("benchmark", help="run every scenario once")
    bench.add_argument("--db", default="necroshield.db")
    run = sub.add_parser("run", help="run a baseline/protected pair")
    run.add_argument("scenario", choices=sorted(REGISTRY))
    run.add_argument("--db", default="necroshield.db")
    run.add_argument("--export", help="write the pair export to this new JSON file")
    reset = sub.add_parser("reset-store", help="delete all stored runs (demo reset)")
    reset.add_argument("--db", required=True)
    reset.add_argument("--yes", action="store_true", help="confirm deletion")
    live = sub.add_parser("live", help="operator-only live-model experiment")
    live.add_argument("--out", required=True, help="directory for run JSON files and summary.json")
    live.add_argument("--scenarios", default="all", help="comma-separated ids, or all")
    live.add_argument("--modes", default="baseline,protected")
    live.add_argument("--repetitions", type=int, default=1, choices=range(1, 11))
    live.add_argument("--temperature", type=float, default=0.0)
    live.add_argument("--budget-usd", type=float, default=2.0)
    live.add_argument("--ledger", default="live-ledger.json")
    args = parser.parse_args(argv)

    if args.command == "live":
        return _live(args)
    if args.command == "reset-store":
        if not args.yes:
            print("refusing to reset without --yes", file=sys.stderr)
            return 1
        _reset(args.db)
        return 0
    if args.command == "scenarios":
        _list_scenarios(args.pins)
    elif args.command == "benchmark":
        _benchmark(args.db)
    else:
        try:
            _run(args.scenario, args.db, args.export)
        except FileExistsError:
            print(f"refusing to overwrite existing file: {args.export}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
