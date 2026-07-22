"""
app/models/attack_simulation_result.py
SQLAlchemy model for attack simulation findings.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class SimulationType(str, enum.Enum):
    CREDENTIAL_TEST = "credential_test"  # reserved for licensed pentest tool output
    WEB_PROBE = "web_probe"
    EXPOSURE_CHECK = "exposure_check"


class SimSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AttackSimulationResult(Base):
    __tablename__ = "attack_simulation_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    simulation_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    target_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    finding_title: Mapped[str] = mapped_column(String(255), nullable=False)
    finding_detail: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    was_successful: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    context_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    simulated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    asset = relationship("Asset", backref="attack_simulation_results", lazy="noload")
