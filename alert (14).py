from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import Boolean, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin


class Tenant(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, unique=True)
    logo_url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    plan: Mapped[str] = mapped_column(String(50), nullable=False, default="standard")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    max_assets: Mapped[int] = mapped_column(nullable=False, default=1000)
    settings: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON blob

    # Relationships
    users: Mapped[list["User"]] = relationship("User", back_populates="tenant", lazy="noload")
    assets: Mapped[list["Asset"]] = relationship("Asset", back_populates="tenant", lazy="noload")
