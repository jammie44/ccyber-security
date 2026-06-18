from __future__ import annotations

import uuid
from enum import Enum
from typing import Optional

from sqlalchemy import Boolean, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin


class AssetType(str, Enum):
    PHYSICAL_SERVER = "physical_server"
    CLOUD_VM = "cloud_vm"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    CONTAINER = "container"
    WEB_APPLICATION = "web_application"
    DATABASE = "database"
    CLOUD_STORAGE = "cloud_storage"
    CLOUD_FUNCTION = "cloud_function"
    MOBILE_DEVICE = "mobile_device"
    IOT_DEVICE = "iot_device"
    API_ENDPOINT = "api_endpoint"
    CERTIFICATE = "certificate"
    OTHER = "other"


class AssetStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DECOMMISSIONED = "decommissioned"
    UNDER_REVIEW = "under_review"


class ExposureLevel(str, Enum):
    INTERNET = "internet"
    PARTNER = "partner"
    INTERNAL = "internal"
    ISOLATED = "isolated"


class CriticalityLabel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Asset(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "assets"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(100), nullable=False, default=AssetType.OTHER)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default=AssetStatus.ACTIVE)

    # Network / Identity
    ip_addresses: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)  # List[str]
    mac_addresses: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    hostnames: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    fqdn: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    cloud_provider: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    cloud_account_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    cloud_region: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    cloud_resource_id: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # OS / Software
    os_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    os_version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    os_family: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # linux/windows/macos

    # Business context
    environment: Mapped[str] = mapped_column(String(50), nullable=False, default="production")
    business_unit: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    department: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    owner_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    owner_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    criticality_score: Mapped[float] = mapped_column(Float, nullable=False, default=5.0)
    criticality_label: Mapped[str] = mapped_column(String(20), nullable=False, default=CriticalityLabel.MEDIUM)
    business_impact_score: Mapped[float] = mapped_column(Float, nullable=False, default=5.0)
    data_classification: Mapped[str] = mapped_column(String(50), nullable=False, default="internal")
    exposure_level: Mapped[str] = mapped_column(String(50), nullable=False, default=ExposureLevel.INTERNAL)
    is_internet_facing: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_in_compliance_scope: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Discovery metadata
    discovery_source: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    agent_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    agent_last_checkin: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    last_scan_date: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Security metrics (denormalized for performance)
    security_health_score: Mapped[float] = mapped_column(Float, nullable=False, default=70.0)
    open_vuln_critical: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    open_vuln_high: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    open_vuln_medium: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    open_vuln_low: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    current_risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    current_risk_band: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    # Tags and custom attributes
    tags: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    custom_attributes: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="assets", lazy="noload")
    owner: Mapped[Optional["User"]] = relationship("User", foreign_keys=[owner_id], lazy="noload")
