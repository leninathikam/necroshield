"""Independent, standard-library verifier for a downloaded NecroShield pair export.

This verifies internal integrity and dispatch/outcome consistency, not authorship.
It intentionally does not import the application that generated the evidence.
"""

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path


def digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify(data: dict) -> None:
    body = {key: value for key, value in data.items() if key != "export_digest"}
    require(digest(body) == data.get("export_digest"), "Export digest mismatch")
    require(data["replay_mode"] == "deterministic_intent_replay", "Unrecognized replay semantics")
    require(data["execution_kind"] == "synthetic_fixture", "Unrecognized execution kind")
    require(data["baseline"]["id"] != data["protected"]["id"], "Paired run IDs must differ")
    for mode in ("baseline", "protected"):
        run = data[mode]
        require(run["mode"] == mode, f"{mode}: run mode mismatch")
        previous = "0" * 64
        pending: dict | None = None
        executed = denied = 0
        for sequence, event in enumerate(run["events"], 1):
            event_body = {key: value for key, value in event.items() if key != "hash"}
            require(event["sequence"] == sequence, f"{mode}: broken event sequence")
            require(event["previous_hash"] == previous, f"{mode}: broken chain link")
            # The documented event canonicalization hashes datetime.isoformat(),
            # while Pydantic JSON transport represents UTC with a trailing Z.
            event_body["timestamp"] = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")).isoformat()
            require(digest(event_body) == event["hash"], f"{mode}: event {sequence} hash mismatch")
            previous = event["hash"]
            if event["kind"] == "policy.decision":
                require(pending is None, f"{mode}: allowed call has no execution event")
                permitted = {"allow", "deny"} if mode == "protected" else {"bypass"}
                require(event["decision"] in permitted, f"{mode}: decision violates enforcement mode")
                if event["decision"] == "deny":
                    denied += 1
                else:
                    require(event["decision"] in {"allow", "bypass"}, f"{mode}: invalid decision")
                    pending = event
            elif event["kind"] == "tool.executed":
                require(pending is not None, f"{mode}: execution without authorization event")
                require(event["tool"] == pending["tool"] and event["arguments"] == pending["arguments"],
                        f"{mode}: authorized and executed call differ")
                pending = None
                executed += 1
        require(pending is None, f"{mode}: incomplete dispatch")
        require(run["events"][-1]["kind"] == "run.completed", f"{mode}: missing completion evidence")
        outcome = run["events"][-1]["result"]
        require(run["effects"] == outcome["effects"], f"{mode}: inconsistent observed effects")
        for metric in ("attack_success", "legitimate_task_completed"):
            require(run["metrics"][metric] == outcome[metric], f"{mode}: inconsistent {metric}")
        require(run["metrics"]["blocked_executions"] == denied, f"{mode}: denial count mismatch")
        require(run["metrics"]["tool_calls"] == executed, f"{mode}: execution count mismatch")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    path = parser.parse_args().path
    require(path.stat().st_size <= 2_000_000, "Evidence exceeds verifier input limit")
    verify(json.loads(path.read_text(encoding="utf-8")))
    print("PASS: export digest, event chains, dispatch order, and outcome consistency")
    print("LIMIT: internal integrity is not proof of authorship or external notarization")


if __name__ == "__main__":
    try:
        main()
    except (KeyError, TypeError, ValueError, IndexError, OSError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc
