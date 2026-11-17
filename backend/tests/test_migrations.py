from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError
import pytest

from necroshield.engine import execute_pair
from necroshield.scenarios import DOCUMENT_INJECTION
from necroshield.storage import Repository


def test_actual_sqlite_migration_and_append_only_identifier(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'migrated.db'}"
    monkeypatch.setenv("DATABASE_URL", url)
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    command.upgrade(config, "head")
    repository = Repository(url, initialize=False)
    try:
        assert set(inspect(repository.engine).get_table_names()) == {"alembic_version", "run_pairs", "benchmarks"}
        pair = execute_pair(DOCUMENT_INJECTION)
        repository.save(pair)
        assert repository.get(pair.id) == pair
        with pytest.raises(IntegrityError):
            repository.save(pair)
        assert repository.get(pair.id) == pair
    finally:
        repository.close()
    command.downgrade(config, "base")
