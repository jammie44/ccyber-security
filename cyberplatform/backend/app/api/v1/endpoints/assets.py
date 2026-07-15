from __future__ import annotations

import uuid
from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import get_db
from app.middleware.auth import CurrentUser, require_role
from app.models.user import UserRole
from app.schemas.asset import (
    AssetCreate,
    AssetListResponse,
    AssetOut,
    AssetSummary,
    AssetUpdate,
)
from app.services.asset_service import AssetService

router = APIRouter()


@router.get("", response_model=AssetListResponse)
async def list_assets(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    q: Optional[str] = None,
    asset_type: Optional[List[str]] = Query(default=None),
    environment: Optional[str] = None,
    status: Optional[str] = None,
    risk_band: Optional[List[str]] = Query(default=None),
    page: int = 1,
    per_page: int = 50,
) -> AssetListResponse:
    service = AssetService(db)
    items, total = await service.search_assets(
        user.tenant_id,
        q=q,
        asset_type=asset_type,
        environment=environment,
        status=status,
        risk_band=risk_band,
        page=page,
        per_page=per_page,
    )
    return AssetListResponse(
        assets=[AssetOut.model_validate(a) for a in items],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/summary", response_model=AssetSummary)
async def get_asset_summary(user: CurrentUser, db: Annotated[AsyncSession, Depends(get_db)]) -> AssetSummary:
    service = AssetService(db)
    data = await service.get_summary(user.tenant_id)
    return AssetSummary(**data)


@router.post("", response_model=AssetOut, status_code=201)
async def create_asset(
    payload: AssetCreate,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AssetOut:
    service = AssetService(db)
    asset = await service.create_asset(user.tenant_id, payload)
    return AssetOut.model_validate(asset)


@router.get("/{asset_id}", response_model=AssetOut)
async def get_asset(
    asset_id: uuid.UUID,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AssetOut:
    service = AssetService(db)
    asset = await service.get_asset(user.tenant_id, asset_id)
    return AssetOut.model_validate(asset)


@router.patch("/{asset_id}", response_model=AssetOut)
async def update_asset(
    asset_id: uuid.UUID,
    payload: AssetUpdate,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AssetOut:
    service = AssetService(db)
    asset = await service.update_asset(user.tenant_id, asset_id, payload)
    return AssetOut.model_validate(asset)


@router.delete("/{asset_id}", status_code=200)
async def delete_asset(
    asset_id: uuid.UUID,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, require_role(UserRole.ORG_ADMIN)] = None,
) -> dict:
    service = AssetService(db)
    await service.delete_asset(user.tenant_id, asset_id)
    return {"deleted": True}
