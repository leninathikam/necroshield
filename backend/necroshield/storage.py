"""Durable run history in SQLite (stdlib).

Triggers block UPDATE always, and DELETE (including INSERT OR REPLACE) unless the store's own
retention or reset path has opened a maintenance window inside the same transaction. Records
can be removed but never rewritten. This guards against accidents only: anyone with write
access to the file can drop the triggers. Every read re-verifies the stored export with the
standalone verifier, so nothing is shown as a conclusion unverified.

Retention: once the store holds `max_pairs`, the oldest pairs are pruned down to 90% of the
cap. The newest default-policy pair of each scenario definition (the benchmark population) is
never pruned.
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
CREATE TABLE IF NOT EXISTS maintenance (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    deletes_allowed INTEGER NOT NULL
);
INSERT OR IGNORE INTO maintenance VALUES (1, 0);
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
            self._db.execute(
                f"CREATE TRIGGER IF NOT EXISTS {table}_no_update BEFORE UPDATE ON {table} "
                f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END")
            self._db.execute(f"DROP TRIGGER IF EXISTS {table}_no_delete")  # pre-retention schema
            self._db.execute(
                f"CREATE TRIGGER IF NOT EXISTS {table}_guard_delete BEFORE DELETE ON {table} "
                f"WHEN (SELECT deletes_allowed FROM maintenance WHERE id = 1) = 0 "
                f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END")
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    def save(self, pair: PairResult, analysis: list[dict[str, Any]] | None = None) -> None:
        """Store a pair. `analysis` is derived data (counterfactual attribution), kept apart from
        the evidence export and never used to compute verified conclusions."""
        export = pair.export()
        duration = pair.baseline.duration_ms + pair.protected.duration_ms
        with self._lock, self._db:
            if self._db.execute("SELECT COUNT(*) FROM pairs").fetchone()[0] >= self.max_pairs:
                self._prune(max(1, int(self.max_pairs * 0.9)) - 1)
                if self._db.execute("SELECT COUNT(*) FROM pairs").fetchone()[0] >= self.max_pairs:
                    raise StorageFull(f"evidence store is full ({self.max_pairs} pairs, all protected)")
            self._db.execute(
                "INSERT INTO pairs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (pair.pair_id, datetime.now(timezone.utc).isoformat(), pair.scenario.scenario_id,
                 pair.scenario.version, pair.scenario.digest(), pair.policy.digest(), pair.policy_source,
                 duration, canonical_json(export), canonical_json(analysis or [])),
            )
            for run in (pair.baseline, pair.protected):
                self._db.execute("INSERT INTO runs VALUES (?, ?, ?, ?)",
                                 (run.run_id, pair.pair_id, run.mode.value, run.head))

    def _delete(self, pair_ids: list[str]) -> int:
        """Remove whole pairs inside the caller's transaction. The maintenance flag is opened and
        closed within that transaction, so a failure rolls it back to closed."""
        if not pair_ids:
            return 0
        self._db.execute("UPDATE maintenance SET deletes_allowed = 1 WHERE id = 1")
        for start in range(0, len(pair_ids), 500):
            chunk = pair_ids[start:start + 500]
            marks = ",".join("?" * len(chunk))
            self._db.execute(f"DELETE FROM runs WHERE pair_id IN ({marks})", chunk)
            self._db.execute(f"DELETE FROM pairs WHERE pair_id IN ({marks})", chunk)
        self._db.execute("UPDATE maintenance SET deletes_allowed = 0 WHERE id = 1")
        return len(pair_ids)

    def _protected_ids(self) -> set[str]:
        rows = self._db.execute(
            "SELECT pair_id FROM pairs p WHERE policy_source = 'scenario_default' AND created_at = ("
            "SELECT MAX(created_at) FROM pairs q WHERE q.scenario_id = p.scenario_id AND "
            "q.scenario_digest = p.scenario_digest AND q.policy_digest = p.policy_digest AND "
            "q.policy_source = 'scenario_default')").fetchall()
        return {r[0] for r in rows}

    def _prune(self, keep: int) -> int:
        keep_ids = self._protected_ids()
        rows = self._db.execute("SELECT pair_id FROM pairs ORDER BY created_at DESC").fetchall()
        survivors, doomed = 0, []
        for (pair_id,) in rows:
            if pair_id in keep_ids or survivors < keep - len(keep_ids):
                survivors += 1
            else:
                doomed.append(pair_id)
        return self._delete(doomed)

    def reset(self) -> int:
        """Delete every stored pair (demo reset). Returns the number removed."""
        with self._lock, self._db:
            ids = [r[0] for r in self._db.execute("SELECT pair_id FROM pairs").fetchall()]
            return self._delete(ids)

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
