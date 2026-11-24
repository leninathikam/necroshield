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
])
def test_history_is_append_only(pair, tmp_path, statement):
    store = RunStore(tmp_path / "runs.db")
    store.save(pair)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        store._db.execute(statement)
    store.close()


def test_run_ids_cannot_be_reused(pair, tmp_path):
    store = RunStore(tmp_path / "runs.db")
    store.save(pair)
    with pytest.raises(sqlite3.IntegrityError):
        store.save(pair)
    store.close()
