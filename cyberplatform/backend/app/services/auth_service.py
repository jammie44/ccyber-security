from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pyotp
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.core.config import settings
from app.models.tenant import Tenant
from app.models.user import User, UserRole
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse


def _slugify(value: str) -> str:
    return "-".join(value.lower().split())[:100]


class AuthService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def register(self, payload: RegisterRequest) -> TokenResponse:
        existing = await self.db.execute(select(User).where(User.email == payload.email))
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

        slug = payload.tenant_slug or _slugify(payload.tenant_name)
        existing_tenant = await self.db.execute(select(Tenant).where(Tenant.slug == slug))
        if existing_tenant.scalar_one_or_none():
            slug = f"{slug}-{uuid.uuid4().hex[:6]}"

        tenant = Tenant(name=payload.tenant_name, slug=slug, plan="standard")
        self.db.add(tenant)
        await self.db.flush()

        user = User(
            tenant_id=tenant.id,
            email=payload.email,
            full_name=payload.full_name,
            hashed_password=hash_password(payload.password),
            role=UserRole.ORG_ADMIN.value,  # First user of a tenant is org_admin
            is_active=True,
            is_email_verified=False,
        )
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)

        return self._issue_tokens(user)

    async def login(self, payload: LoginRequest) -> TokenResponse:
        result = await self.db.execute(select(User).where(User.email == payload.email))
        user = result.scalar_one_or_none()

        if not user or not user.hashed_password or not verify_password(payload.password, user.hashed_password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        if not user.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is inactive")

        if user.mfa_enabled:
            if not payload.mfa_code:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="MFA code required",
                )
            totp = pyotp.TOTP(user.mfa_secret)
            if not totp.verify(payload.mfa_code, valid_window=1):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA code")

        user.last_login_at = datetime.now(timezone.utc).isoformat()
        await self.db.commit()

        return self._issue_tokens(user)

    async def refresh(self, refresh_token: str) -> TokenResponse:
        try:
            payload = decode_token(refresh_token)
        except Exception:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

        if payload.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

        user_id = payload.get("sub")
        result = await self.db.execute(select(User).where(User.id == uuid.UUID(user_id)))
        user = result.scalar_one_or_none()
        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

        return self._issue_tokens(user)

    async def setup_mfa(self, user: User) -> tuple[str, str]:
        secret = pyotp.random_base32()
        user.mfa_secret = secret
        await self.db.commit()
        totp = pyotp.TOTP(secret)
        qr_uri = totp.provisioning_uri(name=user.email, issuer_name=settings.PROJECT_NAME)
        return secret, qr_uri

    async def verify_and_enable_mfa(self, user: User, code: str) -> None:
        if not user.mfa_secret:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA setup not initiated")
        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(code, valid_window=1):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid MFA code")
        user.mfa_enabled = True
        await self.db.commit()

    async def change_password(self, user: User, current_password: str, new_password: str) -> None:
        if not user.hashed_password or not verify_password(current_password, user.hashed_password):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")
        user.hashed_password = hash_password(new_password)
        await self.db.commit()

    def _issue_tokens(self, user: User) -> TokenResponse:
        access = create_access_token(
            subject=str(user.id),
            extra={"tenant_id": str(user.tenant_id), "role": user.role},
        )
        refresh = create_refresh_token(subject=str(user.id))
        return TokenResponse(
            access_token=access,
            refresh_token=refresh,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )
