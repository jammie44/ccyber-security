"""network monitor tables

Revision ID: 0004
Revises: 0003
Create Date: 2026-07-27
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── unknown_device_events ─────────────────────────────────────────────
    op.create_table(
        "unknown_device_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("mac_address", sa.String(17), nullable=False),
        sa.Column("vendor", sa.String(255), nullable=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("open_ports", postgresql.JSONB(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("alert_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("is_approved", sa.Boolean(), nullable=False,
                  server_default=sa.false()),
        sa.Column("approved_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_unknown_device_tenant_id", "unknown_device_events", ["tenant_id"])
    op.create_index("ix_unknown_device_mac", "unknown_device_events", ["mac_address"])
    op.create_index("ix_unknown_device_approved", "unknown_device_events",
                    ["tenant_id", "is_approved"])

    # ── access_audit_log ──────────────────────────────────────────────────
    op.create_table(
        "access_audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("user_role", sa.String(50), nullable=True),
        sa.Column("endpoint", sa.String(500), nullable=False),
        sa.Column("method", sa.String(10), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.String(500), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("accessed_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index("ix_access_audit_tenant_id", "access_audit_log", ["tenant_id"])
    op.create_index("ix_access_audit_user_id", "access_audit_log", ["user_id"])
    op.create_index("ix_access_audit_accessed_at", "access_audit_log", ["accessed_at"])
    op.create_index("ix_access_audit_tenant_user", "access_audit_log",
                    ["tenant_id", "user_id", "accessed_at"])

    # ── data_protection_findings ──────────────────────────────────────────
    op.create_table(
        "data_protection_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_table", sa.String(100), nullable=False),
        sa.Column("source_record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_field", sa.String(100), nullable=False),
        sa.Column("pii_type", sa.String(50), nullable=False),
        sa.Column("pii_sample", sa.String(20), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("is_resolved", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_dpf_tenant_id", "data_protection_findings", ["tenant_id"])
    op.create_index("ix_dpf_pii_type", "data_protection_findings", ["pii_type"])
    op.create_index("ix_dpf_severity", "data_protection_findings", ["severity"])
    op.create_index("ix_dpf_unresolved", "data_protection_findings",
                    ["tenant_id", "is_resolved"])


def downgrade() -> None:
    op.drop_index("ix_dpf_unresolved", table_name="data_protection_findings")
    op.drop_index("ix_dpf_severity", table_name="data_protection_findings")
    op.drop_index("ix_dpf_pii_type", table_name="data_protection_findings")
    op.drop_index("ix_dpf_tenant_id", table_name="data_protection_findings")
    op.drop_table("data_protection_findings")

    op.drop_index("ix_access_audit_tenant_user", table_name="access_audit_log")
    op.drop_index("ix_access_audit_accessed_at", table_name="access_audit_log")
    op.drop_index("ix_access_audit_user_id", table_name="access_audit_log")
    op.drop_index("ix_access_audit_tenant_id", table_name="access_audit_log")
    op.drop_table("access_audit_log")

    op.drop_index("ix_unknown_device_approved", table_name="unknown_device_events")
    op.drop_index("ix_unknown_device_mac", table_name="unknown_device_events")
    op.drop_index("ix_unknown_device_tenant_id", table_name="unknown_device_events")
    op.drop_table("unknown_device_events")
