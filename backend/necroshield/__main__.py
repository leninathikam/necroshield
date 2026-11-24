"""CLI.

  python -m necroshield scenarios                      list scenarios and the digests to pin
  python -m necroshield run SCENARIO [--db PATH] [--export FILE]
"""

from __future__ import annotations

import argparse
import json
import sys

from .runner import run_pair
from .scenarios import REGISTRY, get_scenario
from .storage import RunStore


def _list_scenarios() -> None:
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="necroshield")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("scenarios", help="list scenarios and their digests")
    run = sub.add_parser("run", help="run a baseline/protected pair")
    run.add_argument("scenario", choices=sorted(REGISTRY))
    run.add_argument("--db", default="necroshield.db")
    run.add_argument("--export", help="write the pair export to this new JSON file")
    args = parser.parse_args(argv)

    if args.command == "scenarios":
        _list_scenarios()
    else:
        try:
            _run(args.scenario, args.db, args.export)
        except FileExistsError:
            print(f"refusing to overwrite existing file: {args.export}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
