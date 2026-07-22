"""
app/models/intelligence.py
AssetRiskPrediction and SecurityPostureSnapshot models.
"""
from __future__ import annotations

import uuid
from datetime import date, datetime, timezone

from sqlalchemy import Date, DateTime, ForeignKey, Integer, Numeric, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base  # fixed — existing codebase uses app.db.base


class AssetRiskPrediction(Base):
    __tablename__ = "asset_risk_predictions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), index=True, nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    predicted_severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    confidence_score: Mapped[float] = mapped_column(Numeric(4, 3), nullable=False)
    prediction_reason: Mapped[str] = mapped_column(Text, nullable=False)
    based_on_asset_count: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    asset = relationship("Asset", backref="risk_predictions", lazy="noload")


class SecurityPostureSnapshot(Base):
    __tablename__ = "security_posture_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), index=True, nullable=False
    )
    snapshot_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    org_risk_score: Mapped[float] = mapped_column(Numeric(5, 2), nullable=False)
    open_critical_vulns: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    open_high_vulns: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sla_compliance_rate: Mapped[float] = mapped_column(Numeric(5, 2), nullable=False, default=0)
    assets_scanned: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    assets_with_exposures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_simulation_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
