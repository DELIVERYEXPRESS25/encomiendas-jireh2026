"""Track failed login attempts and temporary account locks."""

from alembic import op
import sqlalchemy as sa


revision = "d9417a2b1c6e"
down_revision = "c83201d4411a"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "login_locks",
        sa.Column("username", sa.String(length=80), nullable=False),
        sa.Column("failed_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.String(length=40), nullable=False, server_default=""),
        sa.PrimaryKeyConstraint("username"),
    )


def downgrade():
    op.drop_table("login_locks")
