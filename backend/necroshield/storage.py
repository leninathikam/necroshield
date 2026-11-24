"""Durable run history in SQLite (stdlib).

Triggers block UPDATE, DELETE, and INSERT OR REPLACE through this connection. That guards
against accidental rewrites only: anyone with write access to the file can drop the triggers.
Every read re-verifies the stored export with the standalone verifier, and callers receive the
verification problems alongside the data, so nothing is shown as a conclusion unverified.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .contracts import canonical_json
from .runner import PairResult
from .verification import verify_export

SCHEMA = """
CREATE TABLE IF NOT EXISTS pairs (
    pair_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    scenario_id TEXT NOT NULL,
    scenario_version TEXT NOT NULL,
    scenario_digest TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    policy_source TEXT NOT NULL,
    duration_ms REAL NOT NULL,
    export_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    pair_id TEXT NOT NULL REFERENCES pairs(pair_id),
    mode TEXT NOT NULL CHECK (mode IN ('baseline', 'protected')),
    head TEXT NOT NULL,
    UNIQUE (pair_id, mode)
);
"""

_IMMUTABLE = ("pairs", "runs")


@dataclass(frozen=True)
class StoredPair:
    export: dict[str, Any]
    created_at: str
    duration_ms: float
    problems: list[str]

    @property
    def verified(self) -> bool:
        return not self.problems


class RunStore:
    def __init__(self, path: str | Path) -> None:
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.execute("PRAGMA foreign_keys = ON")
        # Without this, INSERT OR REPLACE deletes conflicting rows without firing DELETE triggers.
        self._db.execute("PRAGMA recursive_triggers = ON")
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
        duration = pair.baseline.duration_ms + pair.protected.duration_ms
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO pairs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (pair.pair_id, datetime.now(timezone.utc).isoformat(), pair.scenario.scenario_id,
                 pair.scenario.version, pair.scenario.digest(), pair.policy.digest(), pair.policy_source,
                 duration, canonical_json(export)),
            )
            for run in (pair.baseline, pair.protected):
                self._db.execute("INSERT INTO runs VALUES (?, ?, ?, ?)",
                                 (run.run_id, pair.pair_id, run.mode.value, run.head))

    def _row_to_pair(self, row: tuple) -> StoredPair:
        created, duration, text = row
        export = json.loads(text)
        return StoredPair(export, created, duration, verify_export(export))

    def load(self, pair_id: str) -> StoredPair:
        with self._lock:
            row = self._db.execute(
                "SELECT created_at, duration_ms, export_json FROM pairs WHERE pair_id = ?", (pair_id,)
            ).fetchone()
        if row is None:
            raise KeyError(pair_id)
        return self._row_to_pair(row)

    def recent(self, limit: int = 50) -> list[StoredPair]:
        with self._lock:
            rows = self._db.execute(
                "SELECT created_at, duration_ms, export_json FROM pairs ORDER BY created_at DESC LIMIT ?",
                (max(1, min(limit, 500)),),
            ).fetchall()
        return [self._row_to_pair(r) for r in rows]

    def count(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM pairs").fetchone()[0]
