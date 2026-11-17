import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from necroshield.engine import execute_pair
from necroshield.mcp_server import inspect_run, list_benchmarks
from necroshield.scenarios import DOCUMENT_INJECTION
from necroshield.storage import Repository


def test_inspector_missing_store_does_not_create_directories_or_database(tmp_path, monkeypatch):
    data_dir = tmp_path / "missing" / "evidence"
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("NECROSHIELD_DATA_DIR", str(data_dir))
    with pytest.raises(FileNotFoundError, match="Evidence database is missing"):
        list_benchmarks()
    with pytest.raises(FileNotFoundError, match="Evidence database is missing"):
        inspect_run("4a1c7454-a9bc-4ac2-b6c1-294e0b423624")
    assert not data_dir.parent.exists()


def test_existing_evidence_is_readable_but_sqlite_itself_rejects_writes(tmp_path, monkeypatch):
    database = tmp_path / "evidence with spaces.db"
    url = f"sqlite:///{database}"
    writer = Repository(url)
    pair = execute_pair(DOCUMENT_INJECTION)
    writer.save(pair)
    writer.close()
    monkeypatch.setenv("DATABASE_URL", url)
    assert inspect_run(pair.id)["id"] == pair.id
    assert list_benchmarks() == []
    reader = Repository(url, read_only=True)
    try:
        assert reader.get(pair.id) == pair
        with pytest.raises(PermissionError, match="read-only"):
            reader.save(pair)
        with pytest.raises(OperationalError, match="readonly"):
            with reader.engine.begin() as connection:
                connection.execute(text("DELETE FROM run_pairs"))
        assert reader.get(pair.id) == pair
    finally:
        reader.close()


def test_explicit_missing_sqlite_file_is_not_created(tmp_path):
    database = tmp_path / "missing.db"
    with pytest.raises(FileNotFoundError, match="Evidence database is missing"):
        Repository(f"sqlite:///{database}", read_only=True)
    assert not database.exists()
