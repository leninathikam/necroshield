import json
import sqlite3

import pytest

from necroshield.storage import RunStore


def test_saved_pair_survives_reopen_and_is_verified_on_load(pair, tmp_path):
    db = tmp_path / "runs.db"
    store = RunStore(db)
    store.save(pair)
    store.close()

    reopened = RunStore(db)
    stored = reopened.load(pair.pair_id)
    recent = reopened.recent()
    reopened.close()

    assert stored.export == pair.export()
    assert stored.verified and stored.problems == []
    assert [p.export["pair_id"] for p in recent] == [pair.pair_id]


@pytest.mark.parametrize("statement", [
    "UPDATE pairs SET export_json = '{}'",
    "DELETE FROM runs",
    "INSERT OR REPLACE INTO pairs SELECT pair_id, created_at, scenario_id, scenario_version, scenario_digest, "
    "policy_digest, policy_source, duration_ms, '{}', analysis_json FROM pairs",
])
def test_history_is_append_only_through_the_store_connection(pair, tmp_path, statement):
    store = RunStore(tmp_path / "runs.db")
    store.save(pair)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        store._db.execute(statement)
    assert store.load(pair.pair_id).verified
    store.close()


def test_tampering_with_the_database_file_is_reported_on_load(pair, tmp_path):
    """Triggers are accident protection only. Someone with file access can drop them, so loads verify."""
    db = tmp_path / "runs.db"
    store = RunStore(db)
    store.save(pair)
    store.close()

    raw = sqlite3.connect(db)
    raw.execute("DROP TRIGGER pairs_no_update")
    export = json.loads(raw.execute("SELECT export_json FROM pairs").fetchone()[0])
    export["runs"][1]["outcome"]["attack_succeeded"] = True
    raw.execute("UPDATE pairs SET export_json = ?", (json.dumps(export),))
    raw.commit()
    raw.close()

    stored = RunStore(db).load(pair.pair_id)
    assert not stored.verified
    assert any("outcome disagrees" in p for p in stored.problems)


def test_run_ids_cannot_be_reused(pair, tmp_path):
    store = RunStore(tmp_path / "runs.db")
    store.save(pair)
    with pytest.raises(sqlite3.IntegrityError):
        store.save(pair)
    store.close()


def test_cli_refuses_to_overwrite_evidence_and_records_nothing(tmp_path, capsys):
    from necroshield.__main__ import main

    export = tmp_path / "pair.json"
    export.write_text("earlier evidence")
    assert main(["run", "document_injection", "--db", str(tmp_path / "runs.db"), "--export", str(export)]) == 1
    assert export.read_text() == "earlier evidence"
    store = RunStore(tmp_path / "runs.db")
    assert store.count() == 0
    store.close()
    assert "refusing to overwrite" in capsys.readouterr().err


def test_retention_prunes_oldest_but_keeps_the_benchmark_population(tmp_path):
    from necroshield.catalog import BENIGN_INVOICE, DOCUMENT_INJECTION
    from necroshield.runner import run_pair
    from necroshield.scenarios import Grant, Policy

    custom = Policy("custom/1.0.0", DOCUMENT_INJECTION.policy.grants + (
        Grant("g-any-send", "send_message", {"to": None, "attach": None}),))
    store = RunStore(tmp_path / "runs.db", max_pairs=10)
    benchmark = [run_pair(DOCUMENT_INJECTION), run_pair(BENIGN_INVOICE)]
    for p in benchmark:
        store.save(p)
    for _ in range(25):
        store.save(run_pair(DOCUMENT_INJECTION, custom))
    assert store.count() <= 10
    current = {s.scenario_id: (s.digest(), s.policy.digest()) for s in (DOCUMENT_INJECTION, BENIGN_INVOICE)}
    kept = {p.export["pair_id"] for p in store.latest_default_per_scenario(current)}
    assert kept == {p.pair_id for p in benchmark}
    assert all(p.verified for p in store.recent(50))
    store.close()


def test_reset_removes_everything_and_store_stays_usable(pair, tmp_path):
    store = RunStore(tmp_path / "runs.db")
    store.save(pair)
    assert store.reset() == 1 and store.count() == 0
    from necroshield.catalog import DOCUMENT_INJECTION
    from necroshield.runner import run_pair
    store.save(run_pair(DOCUMENT_INJECTION))
    assert store.count() == 1
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        store._db.execute("DELETE FROM pairs")  # the maintenance window closed again
    store.close()


def test_store_upgrades_a_database_with_the_old_delete_triggers(pair, tmp_path):
    db = tmp_path / "old.db"
    store = RunStore(db)
    store.save(pair)
    store._db.execute("CREATE TRIGGER pairs_no_delete BEFORE DELETE ON pairs BEGIN SELECT RAISE(ABORT, 'old'); END")
    store._db.commit()
    store.close()
    reopened = RunStore(db)
    assert reopened.reset() == 1
    reopened.close()
