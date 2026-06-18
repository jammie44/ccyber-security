from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import Boolean, Float, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin


class AssetRiskScore(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "asset_risk_scores"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)

    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    risk_band: Mapped[str] = mapped_column(String(20), nullable=False, default="minimal")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=100.0)
    score_delta: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    formula_version: Mapped[str] = mapped_column(String(20), nullable=False, default="1.0")
    trigger_event: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Component breakdown
    vuln_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    vuln_contribution: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    exposure_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    exposure_contribution: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    business_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    business_contribution: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    posture_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    posture_contribution: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    blast_radius_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    blast_radius_contribution: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Top risk drivers (denormalized)
    top_drivers: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    input_snapshot: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    # Relationships
    asset: Mapped["Asset"] = relationship("Asset", lazy="noload")


class OrgRiskScore(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "org_risk_scores"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    risk_band: Mapped[str] = mapped_column(String(20), nullable=False, default="minimal")
    score_delta_7d: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    score_delta_30d: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    trend_direction: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    trend_velocity: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    projection_30d: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    assets_assessed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    assets_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    critical_assets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high_risk_assets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class RiskWeightConfig(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "risk_weight_configs"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    vuln_weight: Mapped[float] = mapped_column(Float, nullable=False, default=0.35)
    exposure_weight: Mapped[float] = mapped_column(Float, nullable=False, default=0.25)
    business_weight: Mapped[float] = mapped_column(Float, nullable=False, default=0.20)
    posture_weight: Mapped[float] = mapped_column(Float, nullable=False, default=0.15)
    blast_radius_weight: Mapped[float] = mapped_column(Float, nullable=False, default=0.05)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    description: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
