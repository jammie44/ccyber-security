from __future__ import annotations

import uuid
from enum import Enum
from typing import Optional

from sqlalchemy import Boolean, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDMixin


class UserRole(str, Enum):
    # Platform roles
    SUPER_ADMIN = "super_admin"
    # Tenant roles (ordered by privilege level)
    ORG_ADMIN = "org_admin"
    SECURITY_MANAGER = "security_manager"
    ANALYST = "analyst"
    AUDITOR = "auditor"
    ASSET_OWNER = "asset_owner"
    EXECUTIVE_VIEWER = "executive_viewer"
    VIEWER = "viewer"


# Role privilege ordering (higher index = more privilege)
ROLE_HIERARCHY = [
    UserRole.VIEWER,
    UserRole.EXECUTIVE_VIEWER,
    UserRole.ASSET_OWNER,
    UserRole.AUDITOR,
    UserRole.ANALYST,
    UserRole.SECURITY_MANAGER,
    UserRole.ORG_ADMIN,
    UserRole.SUPER_ADMIN,
]


def role_gte(role: UserRole, minimum: UserRole) -> bool:
    """Returns True if role has at least minimum privilege level."""
    try:
        return ROLE_HIERARCHY.index(role) >= ROLE_HIERARCHY.index(minimum)
    except ValueError:
        return False


class User(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "users"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    hashed_password: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    role: Mapped[str] = mapped_column(String(50), nullable=False, default=UserRole.VIEWER)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_email_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    last_login_at: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    avatar_url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    department: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    title: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="users", lazy="noload")
