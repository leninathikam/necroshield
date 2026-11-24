"""Durable, append-only run history in SQLite (stdlib). Triggers block updates and deletes."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .contracts import canonical_json
from .runner import PairResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS pairs (
    pair_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    export_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    pair_id TEXT NOT NULL REFERENCES pairs(pair_id),
    mode TEXT NOT NULL CHECK (mode IN ('baseline', 'protected')),
    scenario_id TEXT NOT NULL,
    scenario_version TEXT NOT NULL,
    head TEXT NOT NULL,
    attack_succeeded INTEGER NOT NULL,
    task_completed INTEGER NOT NULL,
    UNIQUE (pair_id, mode)
);
CREATE TABLE IF NOT EXISTS events (
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    seq INTEGER NOT NULL,
    hash TEXT NOT NULL,
    body_json TEXT NOT NULL,
    PRIMARY KEY (run_id, seq)
);
"""

_IMMUTABLE = ("pairs", "runs", "events")


class RunStore:
    def __init__(self, path: str | Path) -> None:
        self._db = sqlite3.connect(str(path))
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.executescript(SCHEMA)
        for table in _IMMUTABLE:
            for op in ("UPDATE", "DELETE"):
                self._db.execute(
                    f"CREATE TRIGGER IF NOT EXISTS {table}_no_{op.lower()} BEFORE {op} ON {table} "
                    f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END"
                )
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    def save(self, pair: PairResult) -> None:
        export = pair.export()
        with self._db:
            self._db.execute(
                "INSERT INTO pairs VALUES (?, ?, ?)",
                (pair.pair_id, datetime.now(timezone.utc).isoformat(), canonical_json(export)),
            )
            for run in (pair.baseline, pair.protected):
                self._db.execute(
                    "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (run.run_id, pair.pair_id, run.mode.value, pair.scenario.scenario_id,
                     pair.scenario.version, run.head, int(run.outcome.attack_succeeded),
                     int(run.outcome.task_completed)),
                )
                self._db.executemany(
                    "INSERT INTO events VALUES (?, ?, ?, ?)",
                    [(run.run_id, e["seq"], e["hash"], canonical_json(e)) for e in run.events],
                )

    def load_export(self, pair_id: str) -> dict[str, Any]:
        row = self._db.execute("SELECT export_json FROM pairs WHERE pair_id = ?", (pair_id,)).fetchone()
        if row is None:
            raise KeyError(pair_id)
        return json.loads(row[0])

    def list_pairs(self) -> list[dict[str, Any]]:
        rows = self._db.execute(
            "SELECT p.pair_id, p.created_at, r.scenario_id, r.mode, r.attack_succeeded, r.task_completed "
            "FROM pairs p JOIN runs r USING (pair_id) ORDER BY p.created_at DESC, r.mode"
        ).fetchall()
        pairs: dict[str, dict[str, Any]] = {}
        for pair_id, created, scenario_id, mode, attack, task in rows:
            entry = pairs.setdefault(pair_id, {"pair_id": pair_id, "created_at": created, "scenario_id": scenario_id})
            entry[mode] = {"attack_succeeded": bool(attack), "task_completed": bool(task)}
        return list(pairs.values())
