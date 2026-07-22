"""attack simulation results table

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-27
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "attack_simulation_results",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("simulation_type", sa.String(50), nullable=False),
        sa.Column("target_port", sa.Integer(), nullable=True),
        sa.Column("finding_title", sa.String(255), nullable=False),
        sa.Column("finding_detail", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column(
            "was_successful",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("context_data", postgresql.JSONB(), nullable=True),
        sa.Column(
            "simulated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    op.create_index(
        "ix_attack_sim_tenant_id",
        "attack_simulation_results",
        ["tenant_id"],
    )
    op.create_index(
        "ix_attack_sim_asset_id",
        "attack_simulation_results",
        ["asset_id"],
    )
    op.create_index(
        "ix_attack_sim_severity",
        "attack_simulation_results",
        ["severity"],
    )
    op.create_index(
        "ix_attack_sim_simulated_at",
        "attack_simulation_results",
        ["simulated_at"],
    )
    op.create_index(
        "ix_attack_sim_tenant_severity",
        "attack_simulation_results",
        ["tenant_id", "severity"],
    )
    op.create_index(
        "ix_attack_sim_was_successful",
        "attack_simulation_results",
        ["tenant_id", "was_successful"],
    )


def downgrade() -> None:
    op.drop_index("ix_attack_sim_was_successful", table_name="attack_simulation_results")
    op.drop_index("ix_attack_sim_tenant_severity", table_name="attack_simulation_results")
    op.drop_index("ix_attack_sim_simulated_at", table_name="attack_simulation_results")
    op.drop_index("ix_attack_sim_severity", table_name="attack_simulation_results")
    op.drop_index("ix_attack_sim_asset_id", table_name="attack_simulation_results")
    op.drop_index("ix_attack_sim_tenant_id", table_name="attack_simulation_results")
    op.drop_table("attack_simulation_results")
