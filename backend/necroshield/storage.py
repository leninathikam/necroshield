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
    export_json TEXT NOT NULL,
    analysis_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS pairs_by_created ON pairs (created_at);
CREATE INDEX IF NOT EXISTS pairs_by_scenario ON pairs (scenario_id, policy_source, created_at);
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
    analysis: list[dict[str, Any]]

    @property
    def verified(self) -> bool:
        return not self.problems


class StorageFull(Exception):
    pass


class RunStore:
    def __init__(self, path: str | Path, max_pairs: int = 20000) -> None:
        self.max_pairs = max_pairs
        self._lock = threading.RLock()
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

    def save(self, pair: PairResult, analysis: list[dict[str, Any]] | None = None) -> None:
        """Store a pair. `analysis` is derived data (counterfactual attribution), kept apart from
        the evidence export and never used to compute verified conclusions."""
        export = pair.export()
        duration = pair.baseline.duration_ms + pair.protected.duration_ms
        with self._lock, self._db:
            # History is append-only, so growth is bounded by refusing new pairs past the cap.
            if self._db.execute("SELECT COUNT(*) FROM pairs").fetchone()[0] >= self.max_pairs:
                raise StorageFull(f"evidence store is full ({self.max_pairs} pairs)")
            self._db.execute(
                "INSERT INTO pairs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (pair.pair_id, datetime.now(timezone.utc).isoformat(), pair.scenario.scenario_id,
                 pair.scenario.version, pair.scenario.digest(), pair.policy.digest(), pair.policy_source,
                 duration, canonical_json(export), canonical_json(analysis or [])),
            )
            for run in (pair.baseline, pair.protected):
                self._db.execute("INSERT INTO runs VALUES (?, ?, ?, ?)",
                                 (run.run_id, pair.pair_id, run.mode.value, run.head))

    def _row_to_pair(self, row: tuple) -> StoredPair:
        """Never raises on bad stored data: problems are returned so callers withhold conclusions."""
        pair_id, created, duration, text, analysis, scenario_digest, policy_digest, policy_source = row
        try:
            export = json.loads(text)
        except ValueError:
            return StoredPair({"pair_id": pair_id}, created, duration, ["stored export is not valid JSON"], [])
        problems = verify_export(export)
        if isinstance(export, dict) and not problems:
            # Cross-check the indexed columns and stored heads against the verified export.
            if (export["scenario"]["digest"], export["policy"]["digest"], export["policy"]["source"]) != (
                    scenario_digest, policy_digest, policy_source):
                problems.append("stored columns disagree with the export")
            with self._lock:
                heads = dict(self._db.execute("SELECT mode, head FROM runs WHERE pair_id = ?", (pair_id,)).fetchall())
            if heads != {r["mode"]: r["head"] for r in export["runs"]}:
                problems.append("stored run heads disagree with the export")
        try:
            parsed = json.loads(analysis)
        except ValueError:
            parsed = []
        return StoredPair(export if isinstance(export, dict) else {"pair_id": pair_id}, created, duration,
                          problems, parsed if isinstance(parsed, list) else [])

    def load(self, pair_id: str) -> StoredPair:
        with self._lock:
            row = self._db.execute(
                "SELECT pair_id, created_at, duration_ms, export_json, analysis_json, scenario_digest, policy_digest, policy_source FROM pairs WHERE pair_id = ?", (pair_id,)
            ).fetchone()
        if row is None:
            raise KeyError(pair_id)
        return self._row_to_pair(row)

    def recent(self, limit: int = 50) -> list[StoredPair]:
        with self._lock:
            rows = self._db.execute(
                "SELECT pair_id, created_at, duration_ms, export_json, analysis_json, scenario_digest, policy_digest, policy_source FROM pairs ORDER BY created_at DESC LIMIT ?",
                (max(1, min(limit, 500)),),
            ).fetchall()
        return [self._row_to_pair(r) for r in rows]

    def latest_default_per_scenario(self, current: dict[str, tuple[str, str]] | None = None) -> list[StoredPair]:
        """The newest scenario-default-policy pair for each scenario: the benchmark population.
        With `current` (scenario id -> (scenario digest, policy digest)), pairs recorded against an
        older definition are skipped, so a version bump never mixes old runs into new metrics."""
        with self._lock:
            if current is not None:
                rows = []
                for scenario_id, (s_digest, p_digest) in sorted(current.items()):
                    row = self._db.execute(
                        "SELECT pair_id, created_at, duration_ms, export_json, analysis_json, scenario_digest, "
                        "policy_digest, policy_source FROM pairs WHERE scenario_id = ? AND policy_source = "
                        "'scenario_default' AND scenario_digest = ? AND policy_digest = ? "
                        "ORDER BY created_at DESC LIMIT 1", (scenario_id, s_digest, p_digest)).fetchone()
                    if row:
                        rows.append(row)
                return [self._row_to_pair(r) for r in rows]
            rows = self._db.execute(
                "SELECT pair_id, created_at, duration_ms, export_json, analysis_json, scenario_digest, policy_digest, policy_source FROM pairs p "
                "WHERE policy_source = 'scenario_default' AND created_at = (SELECT MAX(created_at) FROM pairs q "
                "WHERE q.scenario_id = p.scenario_id AND q.policy_source = 'scenario_default') ORDER BY scenario_id"
            ).fetchall()
        return [self._row_to_pair(r) for r in rows]

    def count(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM pairs").fetchone()[0]
