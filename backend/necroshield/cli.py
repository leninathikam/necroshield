"""Reproducible fixture benchmark and portable evidence verification."""

import argparse
import json
from pathlib import Path

from .contracts import Event
from .evidence import canonical_hash, export_pair, verify_chain
from .main import run_benchmark
from .storage import Repository


def verify_export(data: dict) -> bool:
    digest = data.get("export_digest")
    body = {key: value for key, value in data.items() if key != "export_digest"}
    if not isinstance(digest, str) or digest != canonical_hash(body):
        return False
    return all(verify_chain([Event.model_validate(e) for e in data[mode]["events"]])
               for mode in ("baseline", "protected"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Write benchmark summary and redacted pair evidence")
    parser.add_argument("--verify", type=Path, help="Verify one exported run-pair evidence JSON")
    args = parser.parse_args()
    if args.verify:
        try:
            valid = verify_export(json.loads(args.verify.read_text(encoding="utf-8")))
        except (ValueError, KeyError, TypeError):
            valid = False
        print(json.dumps({"valid": valid}))
        raise SystemExit(0 if valid else 1)
    repository = Repository()
    try:
        benchmark = run_benchmark(repository)
        data = {"benchmark": benchmark.model_dump(mode="json"), "pairs": [
            export_pair(repository.get(pair_id)) for pair_id in benchmark.pair_ids]}
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(benchmark.model_dump(mode="json"), indent=2))
    finally:
        repository.close()


if __name__ == "__main__":
    main()
