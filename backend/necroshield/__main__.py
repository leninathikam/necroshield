"""CLI.

  python -m necroshield scenarios                      list scenarios and the digests to pin
  python -m necroshield run SCENARIO [--db PATH] [--export FILE]
  python -m necroshield benchmark [--db PATH]          run every scenario once and print the table
  python -m necroshield evolve [--variants N] [--out FILE]   closed-loop policy evaluation (keyless)
  python -m necroshield patch SCENARIO --base STRATEGY [--base-from SCENARIO] --out FILE   compile a security patch
  python -m necroshield check-patch FILE                  re-check a patch from its own contents
  python -m necroshield keygen --out KEYFILE            create an Ed25519 signing key (prints the public key)
  python -m necroshield sign FILE --key-file KEYFILE --out SIGNED.json   sign a verified export or bundle
  python -m necroshield reset-store --db PATH --yes    delete all stored runs (demo reset)
  python -m necroshield live --out DIR [...]           operator-only live-model experiment (paid; budgeted)
"""

from __future__ import annotations

import argparse
import json
import sys

from .runner import decisive_denials, run_pair
from .catalog import REGISTRY, get_scenario
from .corpus import CORPUS as _CORPUS

CORPUS_IDS = [sid for sid, s in _CORPUS.items() if s.kind == "attack"]
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


def _evolve(variants: int, out: str | None) -> int:
    from .optimizer import evolve

    handle = open(out, "x", encoding="utf-8") if out else None  # never overwrite earlier results
    try:
        result = evolve(variants)
        c = result["corpus"]
        print(f"corpus: {c['scenarios']} scenarios ({c['attack_scenarios']} attacks in {c['attack_classes']} classes, "
              f"{c['control_scenarios']} controls); development {c['development']['scenarios']}, held-out {c['held_out']['scenarios']}; "
              f"{c['variants_per_attack']} seeded variants per attack")

        def cell(rate):
            return "n/a" if rate["value"] is None else f"{rate['numerator']}/{rate['denominator']}"

        print(f"{'strategy':24} {'feas':5} {'front':5} {'sel':3} | dev: prev  transfer comp   fp-calls cmplx | held-out: prev  transfer comp   fp-calls")
        for s in result["strategies"]:
            d, h = s["development"], s["held_out"]
            print(f"{s['name']:24} {str(s['feasible'])[0]:5} {str(s['on_frontier'])[0]:5} {str(s['selected'])[0]:3} | "
                  f"     {cell(d['forbidden_effects_prevented']):5} {cell(d['transfer_prevented']):8} {cell(d['task_completion']):6} "
                  f"{cell(d['false_positive_calls']):8} {d['complexity_mean']:<5} |           {cell(h['forbidden_effects_prevented']):5} "
                  f"{cell(h['transfer_prevented']):8} {cell(h['task_completion']):6} {cell(h['false_positive_calls'])}")
        print(f"selected (suggestion, not proof of optimality): {result['selected']}")
        for label in ("development", "held_out"):
            print(f"arms on {label}:")
            for arm in result["arms"][label]:
                s = arm["score"]
                print(f"  {arm['arm']:22} prevented {cell(s['forbidden_effects_prevented']):5} completion {cell(s['task_completion']):6} "
                      f"fp-calls {cell(s['false_positive_calls']):7} denial {cell(s['denial_rate'])}")
        if handle:
            json.dump(result, handle, indent=2)
            print(f"results written to {out}")
        return 0
    finally:
        if handle:
            handle.close()


def _patch(args: argparse.Namespace) -> int:
    from .patches import check_patch, compile_patch

    try:
        patch = compile_patch(args.scenario, args.base, args.target, args.base_from)
    except ValueError as exc:
        print(f"no patch: {exc}", file=sys.stderr)
        return 1
    with open(args.out, "x", encoding="utf-8") as handle:
        json.dump(patch, handle, indent=2)
    problems = check_patch(patch)
    print(f"patch {patch['patch_id']} for {args.scenario}: {len(patch['operations'])} operations, "
          f"{sum(r['passed'] for r in patch['results'])}/{len(patch['results'])} regression cases pass, status {patch['activation']['status']}")
    print("\n".join(f"  {line}" for line in patch["explanation"]))
    print(f"written to {args.out}" + ("" if not problems else f"; re-check FAILED: {problems}"))
    return 0 if not problems and patch["all_cases_pass"] else 1


def _check_patch(path: str) -> int:
    from pathlib import Path

    from .patches import check_patch

    problems = check_patch(json.loads(Path(path).read_text(encoding="utf-8")))
    print("OK: every claim in the patch reproduced" if not problems else "FAIL\n" + "\n".join(f"  - {p}" for p in problems))
    return 0 if not problems else 1


def _keygen(out: str) -> int:
    from .signing import generate_keypair, write_key_file

    seed, public = generate_keypair()
    write_key_file(out, seed)  # exclusive create, mode 0600
    print(f"private key written to {out} (keep it out of the repository and off the web server's public paths)")
    print(f"public key (hex, give this to verifiers): {public}")
    return 0


def _sign(path: str, key_file: str, out: str) -> int:
    from pathlib import Path

    from .signing import signer_from_seed_b64
    from .verification import verify_export

    document = json.loads(Path(path).read_text(encoding="utf-8"))
    problems = verify_export(document)
    if problems:
        print("refusing to sign evidence that failed verification:", *problems, sep="\n  - ", file=sys.stderr)
        return 1
    signed = signer_from_seed_b64(Path(key_file).read_text()).sign(document)
    with open(out, "x", encoding="utf-8") as handle:  # never overwrite
        json.dump(signed, handle, indent=2)
    print(f"signed {path} -> {out} (key {signed['signature']['key_id']})")
    return 0


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
    patch_cmd = sub.add_parser("patch", help="compile a security patch from an observed failure")
    patch_cmd.add_argument("scenario", choices=sorted(CORPUS_IDS))
    patch_cmd.add_argument("--base", default="tool_allowlist", choices=["allow_all", "tool_allowlist", "violation_patch"])
    patch_cmd.add_argument("--base-from", dest="base_from", help="scenario whose policy was deployed (same trusted task)")
    patch_cmd.add_argument("--target", default="scoped_trace", choices=["scoped_trace", "exact_trace", "violation_patch"])
    patch_cmd.add_argument("--out", required=True)
    check = sub.add_parser("check-patch", help="re-check a patch file from its own contents")
    check.add_argument("file")
    keygen = sub.add_parser("keygen", help="create an Ed25519 signing key file")
    keygen.add_argument("--out", required=True)
    sign = sub.add_parser("sign", help="sign a verified export or bundle")
    sign.add_argument("file")
    sign.add_argument("--key-file", required=True)
    sign.add_argument("--out", required=True)
    evo = sub.add_parser("evolve", help="closed-loop policy evaluation over the corpus (keyless)")
    evo.add_argument("--variants", type=int, default=3, choices=range(0, 7))
    evo.add_argument("--out", help="write the full results to this new JSON file")
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
    if args.command == "check-patch":
        return _check_patch(args.file)
    if args.command == "patch":
        try:
            return _patch(args)
        except FileExistsError:
            print(f"refusing to overwrite existing file: {args.out}", file=sys.stderr)
            return 1
    if args.command in ("keygen", "sign"):
        try:
            return _keygen(args.out) if args.command == "keygen" else _sign(args.file, args.key_file, args.out)
        except FileExistsError:
            print(f"refusing to overwrite existing file: {args.out}", file=sys.stderr)
            return 1
    if args.command == "evolve":
        try:
            return _evolve(args.variants, args.out)
        except FileExistsError:
            print(f"refusing to overwrite existing file: {args.out}", file=sys.stderr)
            return 1
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
