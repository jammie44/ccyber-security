"""create report_log table

Revision ID: 0005
Revises: 0004
Create Date: 2026-07-29
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "report_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("report_type", sa.String(length=50), nullable=False),
        sa.Column("generated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "generated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("file_size_bytes", sa.Integer(), nullable=True),
        sa.Column("recipient_count", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="success"),
    )
    op.create_index("ix_report_log_tenant_id", "report_log", ["tenant_id"])
    op.create_index("ix_report_log_report_type", "report_log", ["report_type"])
    op.create_index("ix_report_log_generated_at", "report_log", ["generated_at"])


def downgrade() -> None:
    op.drop_index("ix_report_log_generated_at", table_name="report_log")
    op.drop_index("ix_report_log_report_type", table_name="report_log")
    op.drop_index("ix_report_log_tenant_id", table_name="report_log")
    op.drop_table("report_log")
