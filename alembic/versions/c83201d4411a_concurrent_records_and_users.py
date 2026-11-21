"""Add per-record versions, audit attribution, and individual team accounts."""
from alembic import op
import sqlalchemy as sa

revision = "c83201d4411a"
down_revision = "a51c9001bd21"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("shipments") as batch:
        batch.add_column(sa.Column("version", sa.Integer(), nullable=False, server_default="1"))
    with op.batch_alter_table("travel_costs") as batch:
        batch.add_column(sa.Column("version", sa.Integer(), nullable=False, server_default="1"))
    with op.batch_alter_table("database_audit") as batch:
        batch.add_column(sa.Column("actor", sa.String(length=80), nullable=False, server_default="admin"))
        batch.add_column(sa.Column("action", sa.String(length=32), nullable=False, server_default="replace"))
        batch.add_column(sa.Column("record_type", sa.String(length=32), nullable=False, server_default="state"))
        batch.add_column(sa.Column("record_id", sa.String(length=80), nullable=False, server_default=""))
    op.create_table(
        "team_users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=40), nullable=False),
        sa.Column("display_name", sa.String(length=100), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("credential_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.String(length=32), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_team_users_username", "team_users", ["username"], unique=True)


def downgrade():
    op.drop_index("ix_team_users_username", table_name="team_users")
    op.drop_table("team_users")
    with op.batch_alter_table("database_audit") as batch:
        batch.drop_column("record_id")
        batch.drop_column("record_type")
        batch.drop_column("action")
        batch.drop_column("actor")
    with op.batch_alter_table("travel_costs") as batch:
        batch.drop_column("version")
    with op.batch_alter_table("shipments") as batch:
        batch.drop_column("version")
