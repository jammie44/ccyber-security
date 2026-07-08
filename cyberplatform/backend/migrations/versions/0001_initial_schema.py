"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-06-17

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')

    # ── tenants ───────────────────────────────────────────────────────────
    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), nullable=False, unique=True),
        sa.Column("domain", sa.String(255), nullable=True, unique=True),
        sa.Column("logo_url", sa.String(2048), nullable=True),
        sa.Column("plan", sa.String(50), nullable=False, server_default="standard"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("max_assets", sa.Integer, nullable=False, server_default="1000"),
        sa.Column("settings", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # ── users ─────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=True),
        sa.Column("role", sa.String(50), nullable=False, server_default="viewer"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("is_email_verified", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("mfa_enabled", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("mfa_secret", sa.String(255), nullable=True),
        sa.Column("last_login_at", sa.String(50), nullable=True),
        sa.Column("avatar_url", sa.String(2048), nullable=True),
        sa.Column("department", sa.String(255), nullable=True),
        sa.Column("title", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"])
    op.create_index("ix_users_email", "users", ["email"])

    # ── assets ────────────────────────────────────────────────────────────
    op.create_table(
        "assets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(500), nullable=False),
        sa.Column("asset_type", sa.String(100), nullable=False, server_default="other"),
        sa.Column("status", sa.String(50), nullable=False, server_default="active"),
        sa.Column("ip_addresses", postgresql.JSONB, nullable=True),
        sa.Column("mac_addresses", postgresql.JSONB, nullable=True),
        sa.Column("hostnames", postgresql.JSONB, nullable=True),
        sa.Column("fqdn", sa.String(500), nullable=True),
        sa.Column("cloud_provider", sa.String(50), nullable=True),
        sa.Column("cloud_account_id", sa.String(255), nullable=True),
        sa.Column("cloud_region", sa.String(100), nullable=True),
        sa.Column("cloud_resource_id", sa.String(500), nullable=True),
        sa.Column("os_name", sa.String(255), nullable=True),
        sa.Column("os_version", sa.String(100), nullable=True),
        sa.Column("os_family", sa.String(50), nullable=True),
        sa.Column("environment", sa.String(50), nullable=False, server_default="production"),
        sa.Column("business_unit", sa.String(255), nullable=True),
        sa.Column("department", sa.String(255), nullable=True),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("owner_email", sa.String(255), nullable=True),
        sa.Column("criticality_score", sa.Float, nullable=False, server_default="5.0"),
        sa.Column("criticality_label", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("business_impact_score", sa.Float, nullable=False, server_default="5.0"),
        sa.Column("data_classification", sa.String(50), nullable=False, server_default="internal"),
        sa.Column("exposure_level", sa.String(50), nullable=False, server_default="internal"),
        sa.Column("is_internet_facing", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("is_in_compliance_scope", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("discovery_source", sa.String(100), nullable=True),
        sa.Column("agent_id", sa.String(255), nullable=True),
        sa.Column("agent_last_checkin", sa.String(50), nullable=True),
        sa.Column("last_scan_date", sa.String(50), nullable=True),
        sa.Column("security_health_score", sa.Float, nullable=False, server_default="70.0"),
        sa.Column("open_vuln_critical", sa.Integer, nullable=False, server_default="0"),
        sa.Column("open_vuln_high", sa.Integer, nullable=False, server_default="0"),
        sa.Column("open_vuln_medium", sa.Integer, nullable=False, server_default="0"),
        sa.Column("open_vuln_low", sa.Integer, nullable=False, server_default="0"),
        sa.Column("current_risk_score", sa.Float, nullable=True),
        sa.Column("current_risk_band", sa.String(20), nullable=True),
        sa.Column("tags", postgresql.JSONB, nullable=True),
        sa.Column("custom_attributes", postgresql.JSONB, nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("is_deleted", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_assets_tenant_id", "assets", ["tenant_id"])
    op.create_index("ix_assets_tenant_status", "assets", ["tenant_id", "status"])
    op.create_index("ix_assets_tenant_risk_band", "assets", ["tenant_id", "current_risk_band"])

    # ── cve_records ───────────────────────────────────────────────────────
    op.create_table(
        "cve_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("cve_id", sa.String(20), nullable=False, unique=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("cvss_v3_score", sa.Float, nullable=True),
        sa.Column("cvss_v3_vector", sa.String(255), nullable=True),
        sa.Column("cvss_v3_base_severity", sa.String(20), nullable=True),
        sa.Column("cvss_v2_score", sa.Float, nullable=True),
        sa.Column("epss_score", sa.Float, nullable=True),
        sa.Column("epss_percentile", sa.Float, nullable=True),
        sa.Column("is_in_kev", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("kev_date_added", sa.String(20), nullable=True),
        sa.Column("exploit_maturity", sa.String(50), nullable=True),
        sa.Column("has_public_exploit", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("cpe_matches", postgresql.JSONB, nullable=True),
        sa.Column("affected_products", postgresql.JSONB, nullable=True),
        sa.Column("references", postgresql.JSONB, nullable=True),
        sa.Column("vendor_advisories", postgresql.JSONB, nullable=True),
        sa.Column("published_date", sa.String(30), nullable=True),
        sa.Column("modified_date", sa.String(30), nullable=True),
        sa.Column("nvd_last_synced", sa.String(30), nullable=True),
        sa.Column("epss_last_updated", sa.String(30), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_cve_records_cve_id", "cve_records", ["cve_id"])

    # ── asset_vulnerabilities ─────────────────────────────────────────────
    op.create_table(
        "asset_vulnerabilities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("cve_id_fk", postgresql.UUID(as_uuid=True), sa.ForeignKey("cve_records.id", ondelete="SET NULL"), nullable=True),
        sa.Column("cve_id", sa.String(20), nullable=True),
        sa.Column("priority", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("status", sa.String(50), nullable=False, server_default="discovered"),
        sa.Column("affected_component", sa.String(500), nullable=True),
        sa.Column("affected_version", sa.String(100), nullable=True),
        sa.Column("fix_version", sa.String(100), nullable=True),
        sa.Column("detection_source", sa.String(100), nullable=True),
        sa.Column("risk_score", sa.Float, nullable=True),
        sa.Column("sla_status", sa.String(20), nullable=False, server_default="on_track"),
        sa.Column("sla_deadline", sa.String(30), nullable=True),
        sa.Column("first_detected_at", sa.String(30), nullable=True),
        sa.Column("triaged_at", sa.String(30), nullable=True),
        sa.Column("assigned_to", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("remediated_at", sa.String(30), nullable=True),
        sa.Column("verified_at", sa.String(30), nullable=True),
        sa.Column("false_positive_reason", sa.Text, nullable=True),
        sa.Column("accepted_risk_reason", sa.Text, nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("evidence", postgresql.JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_asset_vulns_tenant_id", "asset_vulnerabilities", ["tenant_id"])
    op.create_index("ix_asset_vulns_asset_id", "asset_vulnerabilities", ["asset_id"])
    op.create_index("ix_asset_vulns_cve_id", "asset_vulnerabilities", ["cve_id"])
    op.create_index("ix_asset_vulns_tenant_status", "asset_vulnerabilities", ["tenant_id", "status"])

    # ── asset_risk_scores ─────────────────────────────────────────────────
    op.create_table(
        "asset_risk_scores",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("risk_score", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("risk_band", sa.String(20), nullable=False, server_default="minimal"),
        sa.Column("confidence", sa.Float, nullable=False, server_default="100.0"),
        sa.Column("score_delta", sa.Float, nullable=True),
        sa.Column("formula_version", sa.String(20), nullable=False, server_default="1.0"),
        sa.Column("trigger_event", sa.String(100), nullable=True),
        sa.Column("vuln_score", sa.Float, nullable=True),
        sa.Column("vuln_contribution", sa.Float, nullable=True),
        sa.Column("exposure_score", sa.Float, nullable=True),
        sa.Column("exposure_contribution", sa.Float, nullable=True),
        sa.Column("business_score", sa.Float, nullable=True),
        sa.Column("business_contribution", sa.Float, nullable=True),
        sa.Column("posture_score", sa.Float, nullable=True),
        sa.Column("posture_contribution", sa.Float, nullable=True),
        sa.Column("blast_radius_score", sa.Float, nullable=True),
        sa.Column("blast_radius_contribution", sa.Float, nullable=True),
        sa.Column("top_drivers", postgresql.JSONB, nullable=True),
        sa.Column("input_snapshot", postgresql.JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_asset_risk_scores_tenant_id", "asset_risk_scores", ["tenant_id"])

    # ── org_risk_scores ───────────────────────────────────────────────────
    op.create_table(
        "org_risk_scores",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("risk_score", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("risk_band", sa.String(20), nullable=False, server_default="minimal"),
        sa.Column("score_delta_7d", sa.Float, nullable=True),
        sa.Column("score_delta_30d", sa.Float, nullable=True),
        sa.Column("trend_direction", sa.String(20), nullable=True),
        sa.Column("trend_velocity", sa.Float, nullable=True),
        sa.Column("projection_30d", sa.Float, nullable=True),
        sa.Column("assets_assessed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("assets_total", sa.Integer, nullable=False, server_default="0"),
        sa.Column("critical_assets", sa.Integer, nullable=False, server_default="0"),
        sa.Column("high_risk_assets", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # ── risk_weight_configs ───────────────────────────────────────────────
    op.create_table(
        "risk_weight_configs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("vuln_weight", sa.Float, nullable=False, server_default="0.35"),
        sa.Column("exposure_weight", sa.Float, nullable=False, server_default="0.25"),
        sa.Column("business_weight", sa.Float, nullable=False, server_default="0.20"),
        sa.Column("posture_weight", sa.Float, nullable=False, server_default="0.15"),
        sa.Column("blast_radius_weight", sa.Float, nullable=False, server_default="0.05"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("description", sa.String(500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_risk_weight_configs_tenant_id", "risk_weight_configs", ["tenant_id"])

    # ── alert_rules ───────────────────────────────────────────────────────
    op.create_table(
        "alert_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("trigger_type", sa.String(50), nullable=False, server_default="event_based"),
        sa.Column("event_types", postgresql.JSONB, nullable=True),
        sa.Column("condition", postgresql.JSONB, nullable=True),
        sa.Column("schedule", sa.String(100), nullable=True),
        sa.Column("asset_types", postgresql.JSONB, nullable=True),
        sa.Column("environments", postgresql.JSONB, nullable=True),
        sa.Column("severity", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("title_template", sa.String(500), nullable=False),
        sa.Column("message_template", sa.Text, nullable=True),
        sa.Column("auto_resolve", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("notification_channels", postgresql.JSONB, nullable=True),
        sa.Column("notification_targets", postgresql.JSONB, nullable=True),
        sa.Column("dedup_key_fields", postgresql.JSONB, nullable=True),
        sa.Column("dedup_window_minutes", sa.Integer, nullable=False, server_default="60"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("is_builtin", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_alert_rules_tenant_id", "alert_rules", ["tenant_id"])

    # ── alerts ────────────────────────────────────────────────────────────
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rule_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("alert_rules.id", ondelete="SET NULL"), nullable=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("message", sa.Text, nullable=True),
        sa.Column("severity", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("status", sa.String(20), nullable=False, server_default="open"),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("asset_name", sa.String(500), nullable=True),
        sa.Column("context_data", postgresql.JSONB, nullable=True),
        sa.Column("suppressed_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("triggered_at", sa.String(30), nullable=True),
        sa.Column("acknowledged_at", sa.String(30), nullable=True),
        sa.Column("acknowledged_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("resolved_at", sa.String(30), nullable=True),
        sa.Column("resolved_reason", sa.Text, nullable=True),
        sa.Column("auto_resolved", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_alerts_tenant_id", "alerts", ["tenant_id"])
    op.create_index("ix_alerts_tenant_status", "alerts", ["tenant_id", "status"])
    op.create_index("ix_alerts_fingerprint", "alerts", ["tenant_id", "fingerprint"])


def downgrade() -> None:
    op.drop_table("alerts")
    op.drop_table("alert_rules")
    op.drop_table("risk_weight_configs")
    op.drop_table("org_risk_scores")
    op.drop_table("asset_risk_scores")
    op.drop_table("asset_vulnerabilities")
    op.drop_table("cve_records")
    op.drop_table("assets")
    op.drop_table("users")
    op.drop_table("tenants")
