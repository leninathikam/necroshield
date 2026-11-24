#!/usr/bin/env python3
"""Standalone verifier for NecroShield pair exports. Uses only the standard library and
deliberately imports nothing from the application.

Checks: format, run identity, hash links, event order, intent replay, and dispatch rules.
Limit: a fully recomputed forgery of an entire export passes; the chain is not a signature.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

GENESIS = "0" * 64
FORMAT = "necroshield.pair/1"
REPLAY_MODE = "deterministic_intent_replay"


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _verify_run(run: dict, intents: list, problems: list[str]) -> None:
    rid, mode = run.get("run_id"), run.get("mode")
    events = run.get("events") or []
    prev = GENESIS
    for position, event in enumerate(events):
        where = f"run {mode} event {position}"
        if event.get("seq") != position:
            problems.append(f"{where}: seq {event.get('seq')} out of order")
        if event.get("run_id") != rid:
            problems.append(f"{where}: run_id mismatch")
        if event.get("prev_hash") != prev:
            problems.append(f"{where}: prev_hash does not link")
        body = {k: v for k, v in event.items() if k != "hash"}
        expected = hashlib.sha256((prev + _canonical(body)).encode()).hexdigest()
        if event.get("hash") != expected:
            problems.append(f"{where}: hash mismatch")
        prev = event.get("hash", "")
    if run.get("head") != prev:
        problems.append(f"run {mode}: head does not match last event")

    kinds = [e.get("kind") for e in events]
    if not kinds or kinds[0] != "run_started" or kinds[-1] != "run_completed":
        problems.append(f"run {mode}: must start with run_started and end with run_completed")
        return
    started, completed = events[0]["data"], events[-1]["data"]
    if started.get("mode") != mode or started.get("replay_mode") != REPLAY_MODE:
        problems.append(f"run {mode}: run_started mode or replay_mode mismatch")

    calls = [e["data"] for e in events if e.get("kind") == "tool_call"]
    if [c.get("intent_index") for c in calls] != list(range(len(intents))):
        problems.append(f"run {mode}: tool calls do not cover intents in order")
    for call in calls:
        index = call.get("intent_index")
        if isinstance(index, int) and index < len(intents):
            if {"tool": call.get("tool"), "args": call.get("args")} != intents[index]:
                problems.append(f"run {mode}: call {index} differs from intended action")
        if not call.get("allowed") and (call.get("dispatched") or call.get("output") is not None):
            problems.append(f"run {mode}: call {index} was denied but dispatched")
        if mode == "baseline" and not call.get("allowed"):
            problems.append(f"run baseline: call {index} denied without enforcement")

    outcome = run.get("outcome") or {}
    for key in ("attack_succeeded", "task_completed", "observed_effects"):
        if outcome.get(key) != completed.get(key):
            problems.append(f"run {mode}: outcome.{key} disagrees with chained run_completed")


def verify(export: dict) -> list[str]:
    problems: list[str] = []
    if export.get("format") != FORMAT:
        return [f"unsupported format: {export.get('format')!r}"]
    if export.get("replay_mode") != REPLAY_MODE:
        problems.append("replay_mode must be deterministic_intent_replay")
    runs = export.get("runs") or []
    if sorted(r.get("mode") for r in runs) != ["baseline", "protected"]:
        problems.append("export must contain exactly one baseline and one protected run")
    run_ids = [r.get("run_id") for r in runs]
    if len(set(run_ids)) != len(run_ids):
        problems.append("duplicate run_id")
    scenario = export.get("scenario") or {}
    intents = export.get("intents") or []
    for run in runs:
        started = (run.get("events") or [{}])[0].get("data", {})
        if started.get("scenario_digest") != scenario.get("digest"):
            problems.append(f"run {run.get('mode')}: scenario digest differs from export header")
        if started.get("policy_version") != export.get("policy_version"):
            problems.append(f"run {run.get('mode')}: policy version differs from export header")
        _verify_run(run, intents, problems)
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: verify_evidence.py EXPORT.json", file=sys.stderr)
        return 2
    try:
        export = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"FAIL: cannot read export: {exc}")
        return 1
    problems = verify(export) if isinstance(export, dict) else ["export is not a JSON object"]
    if problems:
        print("FAIL")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(f"OK: pair {export['pair_id']} verified ({sum(len(r['events']) for r in export['runs'])} events)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
