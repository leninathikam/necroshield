"""CLI: python -m necroshield run SCENARIO [--db PATH] [--export FILE]"""

from __future__ import annotations

import argparse
import json
import sys

from .runner import run_pair
from .scenarios import REGISTRY, get_scenario
from .storage import RunStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="necroshield")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run a baseline/protected pair")
    run.add_argument("scenario", choices=sorted(REGISTRY))
    run.add_argument("--db", default="necroshield.db")
    run.add_argument("--export", help="write the pair export to this JSON file")
    args = parser.parse_args(argv)

    pair = run_pair(get_scenario(args.scenario))
    store = RunStore(args.db)
    try:
        store.save(pair)
    finally:
        store.close()

    print(f"pair {pair.pair_id}  scenario {pair.scenario.scenario_id}@{pair.scenario.version}  "
          f"replay deterministic_intent_replay")
    for run_result in (pair.baseline, pair.protected):
        denied = sum(not r.decision.allowed for r in run_result.records)
        print(f"  {run_result.mode.value:9} attack_succeeded={run_result.outcome.attack_succeeded!s:5} "
              f"task_completed={run_result.outcome.task_completed!s:5} denied={denied} run {run_result.run_id}")
    if args.export:
        with open(args.export, "w", encoding="utf-8") as handle:
            json.dump(pair.export(), handle, indent=2)
        print(f"  export written to {args.export}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
