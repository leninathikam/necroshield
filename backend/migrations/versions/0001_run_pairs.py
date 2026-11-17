"""Initial immutable run-pair evidence and benchmark schema."""

from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("run_pairs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scenario_id", sa.String(80), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False))
    op.create_index("ix_run_pairs_scenario_id", "run_pairs", ["scenario_id"])
    op.create_index("ix_run_pairs_created_at", "run_pairs", ["created_at"])
    op.create_table("benchmarks",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False))
    op.create_index("ix_benchmarks_created_at", "benchmarks", ["created_at"])


def downgrade():
    op.drop_table("benchmarks")
    op.drop_table("run_pairs")
