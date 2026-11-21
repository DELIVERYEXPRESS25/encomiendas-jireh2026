"""Add a bounded web activity log for the desktop monitor."""

from alembic import op
import sqlalchemy as sa


revision = "a51c9001bd21"
down_revision = "196d61bff023"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "web_activity",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("endpoint", sa.String(length=120), nullable=False),
        sa.Column("method", sa.String(length=12), nullable=False),
        sa.Column("status", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=80), nullable=False),
        sa.Column("remote_addr", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade():
    op.drop_table("web_activity")
