"""create asset_risk_predictions and security_posture_snapshots tables

Revision ID: 0003
Revises: 0002
Create Date: 2026-07-28
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "asset_risk_predictions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("predicted_severity", sa.String(length=20), nullable=False),
        sa.Column("confidence_score", sa.Numeric(4, 3), nullable=False),
        sa.Column("prediction_reason", sa.Text(), nullable=False),
        sa.Column("based_on_asset_count", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_asset_risk_predictions_tenant_id", "asset_risk_predictions", ["tenant_id"]
    )
    op.create_index(
        "ix_asset_risk_predictions_asset_id", "asset_risk_predictions", ["asset_id"]
    )
    op.create_index(
        "ix_asset_risk_predictions_predicted_severity",
        "asset_risk_predictions",
        ["predicted_severity"],
    )
    op.create_index(
        "ix_asset_risk_predictions_created_at", "asset_risk_predictions", ["created_at"]
    )

    op.create_table(
        "security_posture_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("snapshot_date", sa.Date(), nullable=False),
        sa.Column("org_risk_score", sa.Numeric(5, 2), nullable=False),
        sa.Column("open_critical_vulns", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("open_high_vulns", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sla_compliance_rate", sa.Numeric(5, 2), nullable=False, server_default="0"),
        sa.Column("assets_scanned", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("assets_with_exposures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_simulation_findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_security_posture_snapshots_tenant_id",
        "security_posture_snapshots",
        ["tenant_id"],
    )
    op.create_index(
        "ix_security_posture_snapshots_snapshot_date",
        "security_posture_snapshots",
        ["snapshot_date"],
    )
    # Common query pattern is "latest snapshot for tenant" / "snapshot ~7d ago
    # for tenant" -- a composite index makes both fast.
    op.create_index(
        "ix_security_posture_snapshots_tenant_date",
        "security_posture_snapshots",
        ["tenant_id", "snapshot_date"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_security_posture_snapshots_tenant_date", table_name="security_posture_snapshots"
    )
    op.drop_index(
        "ix_security_posture_snapshots_snapshot_date", table_name="security_posture_snapshots"
    )
    op.drop_index(
        "ix_security_posture_snapshots_tenant_id", table_name="security_posture_snapshots"
    )
    op.drop_table("security_posture_snapshots")

    op.drop_index("ix_asset_risk_predictions_created_at", table_name="asset_risk_predictions")
    op.drop_index(
        "ix_asset_risk_predictions_predicted_severity", table_name="asset_risk_predictions"
    )
    op.drop_index("ix_asset_risk_predictions_asset_id", table_name="asset_risk_predictions")
    op.drop_index("ix_asset_risk_predictions_tenant_id", table_name="asset_risk_predictions")
    op.drop_table("asset_risk_predictions")
