"""Opt-in PostgreSQL acceptance; never substitutes SQLite for a PostgreSQL claim."""

import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from necroshield.engine import execute_pair
from necroshield.scenarios import DOCUMENT_INJECTION
from necroshield.storage import Repository


@pytest.mark.skipif(not os.environ.get("NECROSHIELD_TEST_DATABASE_URL"), reason="PostgreSQL test database not configured")
def test_postgres_migration_and_evidence_roundtrip(monkeypatch):
    url = os.environ["NECROSHIELD_TEST_DATABASE_URL"]
    assert url.startswith(("postgres://", "postgresql://", "postgresql+psycopg://"))
    monkeypatch.setenv("DATABASE_URL", url)
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    command.upgrade(config, "head")
    repository = Repository(url)
    try:
        pair = execute_pair(DOCUMENT_INJECTION)
        repository.save(pair)
        assert repository.get(pair.id) == pair
        repository.ping()
        reader = Repository(url, read_only=True)
        try:
            assert reader.get(pair.id) == pair
            with pytest.raises(DBAPIError, match="read-only"):
                with reader.engine.begin() as connection:
                    connection.execute(text("DELETE FROM run_pairs WHERE id = :id"), {"id": pair.id})
        finally:
            reader.close()
    finally:
        repository.close()
