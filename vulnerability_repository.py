from __future__ import annotations

import uuid
from enum import Enum
from typing import Optional

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    AUTO_RESOLVED = "auto_resolved"
    SUPPRESSED = "suppressed"


class AlertRule(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "alert_rules"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    trigger_type: Mapped[str] = mapped_column(String(50), nullable=False, default="event_based")
    event_types: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    condition: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    schedule: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    asset_types: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    environments: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default=AlertSeverity.MEDIUM)
    title_template: Mapped[str] = mapped_column(String(500), nullable=False)
    message_template: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    auto_resolve: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    notification_channels: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    notification_targets: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    dedup_key_fields: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    dedup_window_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Relationships
    alerts: Mapped[list["Alert"]] = relationship("Alert", back_populates="rule", lazy="noload")


class Alert(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "alerts"

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("alert_rules.id", ondelete="SET NULL"), nullable=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default=AlertSeverity.MEDIUM)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default=AlertStatus.OPEN)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    asset_name: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    context_data: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    suppressed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    triggered_at: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    acknowledged_at: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    acknowledged_by: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    resolved_at: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    resolved_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    auto_resolved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Relationships
    rule: Mapped[Optional["AlertRule"]] = relationship("AlertRule", back_populates="alerts", lazy="noload")
    asset: Mapped[Optional["Asset"]] = relationship("Asset", lazy="noload")
