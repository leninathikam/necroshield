"""Append-only application repository over PostgreSQL or local SQLite."""

import os
from datetime import datetime
from pathlib import Path

from sqlalchemy import DateTime, JSON, String, create_engine, event, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from .contracts import Benchmark, RunPair


class Base(DeclarativeBase):
    pass


class PairRecord(Base):
    __tablename__ = "run_pairs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scenario_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False)


class BenchmarkRecord(Base):
    __tablename__ = "benchmarks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False)


def default_database_url(*, create_directory: bool = True) -> str:
    data_dir = Path(os.environ.get("NECROSHIELD_DATA_DIR", "data"))
    if create_directory:
        data_dir.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{data_dir / 'necroshield.db'}"


class Repository:
    def __init__(self, url: str | None = None, *, initialize: bool = True, read_only: bool = False):
        url = url or os.environ.get("DATABASE_URL") or default_database_url(create_directory=not read_only)
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql+psycopg://", 1)
        elif url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+psycopg://", 1)
        parsed = make_url(url)
        self.read_only = read_only
        if read_only and parsed.get_backend_name() == "sqlite":
            if not parsed.database or parsed.database == ":memory:":
                raise ValueError("Read-only inspection requires an existing SQLite evidence file")
            database_path = Path(parsed.database).resolve()
            if not database_path.is_file():
                raise FileNotFoundError("Evidence database is missing; run a benchmark before inspection")
            # SQLite enforces this restriction even for direct SQL through the
            # engine. Opening cannot create a database or run schema DDL.
            parsed = parsed.set(database=database_path.as_uri(),
                                query={**parsed.query, "mode": "ro", "uri": "true"})
        connect_args = {"check_same_thread": False} if parsed.get_backend_name() == "sqlite" else {}
        self.engine = create_engine(parsed, connect_args=connect_args, pool_pre_ping=True)
        self.backend = self.engine.dialect.name
        if read_only and self.backend == "postgresql":
            @event.listens_for(self.engine, "begin")
            def readonly_transaction(connection):
                connection.exec_driver_sql("SET TRANSACTION READ ONLY")
        if initialize and not read_only:
            # Local SQLite is intentionally zero-infrastructure. PostgreSQL must
            # run Alembic explicitly so a production startup never mutates schema.
            if self.backend == "sqlite":
                Base.metadata.create_all(self.engine)

    def save(self, pair: RunPair) -> None:
        if self.read_only:
            raise PermissionError("Evidence inspector repository is read-only")
        with Session(self.engine) as session, session.begin():
            session.add(PairRecord(id=pair.id, scenario_id=pair.scenario_id, created_at=pair.created_at,
                                   evidence=pair.model_dump(mode="json")))

    def get(self, pair_id: str) -> RunPair | None:
        with Session(self.engine) as session:
            record = session.get(PairRecord, pair_id)
            return RunPair.model_validate(record.evidence) if record else None

    def list(self, limit: int = 50) -> list[RunPair]:
        with Session(self.engine) as session:
            records = session.scalars(select(PairRecord).order_by(PairRecord.created_at.desc()).limit(limit))
            return [RunPair.model_validate(record.evidence) for record in records]

    def close(self) -> None:
        self.engine.dispose()

    def ping(self) -> None:
        with Session(self.engine) as session:
            # Checks schema readiness as well as connectivity.
            session.execute(select(PairRecord.id).limit(1))

    def save_benchmark(self, benchmark: Benchmark, pairs: list[RunPair]) -> None:
        if self.read_only:
            raise PermissionError("Evidence inspector repository is read-only")
        # The benchmark and every referenced pair commit atomically.
        with Session(self.engine) as session, session.begin():
            for pair in pairs:
                session.add(PairRecord(id=pair.id, scenario_id=pair.scenario_id,
                    created_at=pair.created_at, evidence=pair.model_dump(mode="json")))
            session.add(BenchmarkRecord(id=benchmark.id, created_at=benchmark.created_at,
                                       evidence=benchmark.model_dump(mode="json")))

    def list_benchmarks(self, limit: int = 20) -> list[Benchmark]:
        with Session(self.engine) as session:
            records = session.scalars(select(BenchmarkRecord).order_by(BenchmarkRecord.created_at.desc()).limit(limit))
            return [Benchmark.model_validate(record.evidence) for record in records]
