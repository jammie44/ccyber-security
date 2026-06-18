from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import get_db
from app.middleware.auth import CurrentUser
from app.schemas.auth import (
    LoginRequest,
    MFASetupResponse,
    MFAVerifyRequest,
    PasswordChangeRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserOut,
)
from app.services.auth_service import AuthService

router = APIRouter()


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(payload: RegisterRequest, db: Annotated[AsyncSession, Depends(get_db)]) -> TokenResponse:
    return await AuthService(db).register(payload)


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, db: Annotated[AsyncSession, Depends(get_db)]) -> TokenResponse:
    return await AuthService(db).login(payload)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(payload: RefreshRequest, db: Annotated[AsyncSession, Depends(get_db)]) -> TokenResponse:
    return await AuthService(db).refresh(payload.refresh_token)


@router.get("/me", response_model=UserOut)
async def get_me(user: CurrentUser) -> UserOut:
    return UserOut.model_validate(user)


@router.post("/change-password", status_code=204)
async def change_password(
    payload: PasswordChangeRequest,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    await AuthService(db).change_password(user, payload.current_password, payload.new_password)


@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(user: CurrentUser, db: Annotated[AsyncSession, Depends(get_db)]) -> MFASetupResponse:
    secret, qr_uri = await AuthService(db).setup_mfa(user)
    return MFASetupResponse(secret=secret, qr_uri=qr_uri, backup_codes=[])


@router.post("/mfa/verify", status_code=204)
async def verify_mfa(
    payload: MFAVerifyRequest,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    await AuthService(db).verify_and_enable_mfa(user, payload.code)
