from __future__ import annotations

import uuid
from enum import Enum
from typing import Optional

from sqlalchemy import Boolean, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin


class VulnPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnStatus(str, Enum):
    DISCOVERED = "discovered"
    TRIAGED = "triaged"
    ASSIGNED = "assigned"
    IN_REMEDIATION = "in_remediation"
    PENDING_VERIFICATION = "pending_verification"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class SLAStatus(str, Enum):
    ON_TRACK = "on_track"
    AT_RISK = "at_risk"
    BREACHED = "breached"
    NOT_APPLICABLE = "not_applicable"


class CVERecord(Base, UUIDMixin, TimestampMixin):
    """Global CVE intelligence record — shared across all tenants."""
    __tablename__ = "cve_records"

    cve_id: Mapped[str] = mapped_column(String(20), nullable=False, unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Scores
    cvss_v3_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_v3_vector: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    cvss_v3_base_severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    cvss_v2_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    epss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Intelligence
    is_in_kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    kev_date_added: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    exploit_maturity: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # weaponized/poc/none
    has_public_exploit: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Affected software
    cpe_matches: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    affected_products: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    # References
    references: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    vendor_advisories: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    # Dates
    published_date: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    modified_date: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    nvd_last_synced: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    epss_last_updated: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)

    # Relationships
    asset_vulnerabilities: Mapped[list["AssetVulnerability"]] = relationship(
        "AssetVulnerability", back_populates="cve", lazy="noload"
    )


class AssetVulnerability(Base, UUIDMixin, TimestampMixin):
    """Tenant-specific asset-CVE pairing with lifecycle management."""
    __tablename__ = "asset_vulnerabilities"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    cve_id_fk: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("cve_records.id", ondelete="SET NULL"), nullable=True)
    cve_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True, index=True)

    # Finding details
    priority: Mapped[str] = mapped_column(String(20), nullable=False, default=VulnPriority.MEDIUM)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default=VulnStatus.DISCOVERED)
    affected_component: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    affected_version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    fix_version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    detection_source: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # SLA tracking
    sla_status: Mapped[str] = mapped_column(String(20), nullable=False, default=SLAStatus.ON_TRACK)
    sla_deadline: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    first_detected_at: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    triaged_at: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    assigned_to: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    remediated_at: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    verified_at: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)

    # Additional context
    false_positive_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    accepted_risk_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    # Relationships
    asset: Mapped["Asset"] = relationship("Asset", lazy="noload")
    cve: Mapped[Optional["CVERecord"]] = relationship("CVERecord", back_populates="asset_vulnerabilities", lazy="noload")
