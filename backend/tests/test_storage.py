import sqlite3

import pytest

from necroshield.storage import RunStore


def test_saved_pair_survives_reopen_and_still_verifies(pair, verifier, tmp_path):
    db = tmp_path / "runs.db"
    store = RunStore(db)
    store.save(pair)
    store.close()

    reopened = RunStore(db)
    export = reopened.load_export(pair.pair_id)
    listing = reopened.list_pairs()
    reopened.close()

    assert export == pair.export()
    assert verifier.verify(export) == []
    assert listing[0]["baseline"]["attack_succeeded"] is True
    assert listing[0]["protected"]["attack_succeeded"] is False


@pytest.mark.parametrize("statement", [
    "UPDATE runs SET attack_succeeded = 0",
    "DELETE FROM events",
    "UPDATE pairs SET export_json = '{}'",
    "INSERT OR REPLACE INTO runs SELECT run_id, pair_id, mode, scenario_id, scenario_version, head, "
    "1, 0 FROM runs WHERE mode = 'protected'",
])
def test_history_is_append_only_through_the_store_connection(pair, tmp_path, statement):
    store = RunStore(tmp_path / "runs.db")
    store.save(pair)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        store._db.execute(statement)
    protected = next(p for p in store.list_pairs())["protected"]
    assert protected == {"attack_succeeded": False, "task_completed": True}
    store.close()


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
    assert store.list_pairs() == []
    store.close()
    assert "refusing to overwrite" in capsys.readouterr().err
