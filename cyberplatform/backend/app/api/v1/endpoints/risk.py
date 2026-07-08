from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import get_db
from app.middleware.auth import CurrentUser, require_role
from app.models.user import UserRole
from app.schemas.risk import (
    AssetRiskScoreOut,
    OrgRiskScoreOut,
    RiskWeightConfigCreate,
    RiskWeightConfigOut,
)
from app.services.risk_service import RiskService

router = APIRouter()


@router.get("/organization", response_model=OrgRiskScoreOut)
async def get_org_risk(user: CurrentUser, db: Annotated[AsyncSession, Depends(get_db)]) -> OrgRiskScoreOut:
    service = RiskService(db)
    org_risk = await service.get_org_risk(user.tenant_id)
    return OrgRiskScoreOut.model_validate(org_risk)


@router.post("/organization/recompute", response_model=OrgRiskScoreOut)
async def recompute_org_risk(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, require_role(UserRole.SECURITY_MANAGER)] = None,
) -> OrgRiskScoreOut:
    service = RiskService(db)
    org_risk = await service.recompute_org_risk(user.tenant_id)
    return OrgRiskScoreOut.model_validate(org_risk)


@router.get("/assets/{asset_id}", response_model=AssetRiskScoreOut)
async def get_asset_risk(
    asset_id: uuid.UUID,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AssetRiskScoreOut:
    service = RiskService(db)
    score = await service.get_asset_risk(user.tenant_id, asset_id)
    return AssetRiskScoreOut(
        asset_id=score.asset_id,
        risk_score=score.risk_score,
        risk_band=score.risk_band,
        confidence=score.confidence,
        score_delta=score.score_delta,
        formula_version=score.formula_version,
        trigger_event=score.trigger_event,
        top_drivers=score.top_drivers,
        computed_at=score.updated_at,
    )


@router.post("/assets/{asset_id}/recompute", response_model=AssetRiskScoreOut)
async def recompute_asset_risk(
    asset_id: uuid.UUID,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AssetRiskScoreOut:
    service = RiskService(db)
    score = await service.compute_and_store_asset_risk(user.tenant_id, asset_id)
    return AssetRiskScoreOut(
        asset_id=score.asset_id,
        risk_score=score.risk_score,
        risk_band=score.risk_band,
        confidence=score.confidence,
        score_delta=score.score_delta,
        formula_version=score.formula_version,
        trigger_event=score.trigger_event,
        top_drivers=score.top_drivers,
        computed_at=score.updated_at,
    )


@router.get("/weights", response_model=list[RiskWeightConfigOut])
async def list_weight_configs(user: CurrentUser, db: Annotated[AsyncSession, Depends(get_db)]):
    from sqlalchemy import select
    from app.models.risk import RiskWeightConfig
    result = await db.execute(select(RiskWeightConfig).where(RiskWeightConfig.tenant_id == user.tenant_id))
    return [RiskWeightConfigOut.model_validate(r) for r in result.scalars().all()]


@router.post("/weights", response_model=RiskWeightConfigOut, status_code=201)
async def create_weight_config(
    payload: RiskWeightConfigCreate,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, require_role(UserRole.SECURITY_MANAGER)] = None,
):
    from app.models.risk import RiskWeightConfig

    total = (
        payload.vuln_weight
        + payload.exposure_weight
        + payload.business_weight
        + payload.posture_weight
        + payload.blast_radius_weight
    )
    if abs(total - 1.0) >= 0.01:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=f"Weights must sum to 1.0, got {total:.4f}")

    config = RiskWeightConfig(
        tenant_id=user.tenant_id,
        name=payload.name,
        vuln_weight=payload.vuln_weight,
        exposure_weight=payload.exposure_weight,
        business_weight=payload.business_weight,
        posture_weight=payload.posture_weight,
        blast_radius_weight=payload.blast_radius_weight,
        description=payload.description,
        is_active=True,
    )
    db.add(config)
    await db.commit()
    await db.refresh(config)
    return RiskWeightConfigOut.model_validate(config)
