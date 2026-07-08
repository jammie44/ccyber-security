from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import get_db
from app.db.redis_client import get_redis
from app.middleware.auth import CurrentUser
from app.models.asset import Asset
from app.schemas.ai import ExplainResponse, ExplainRiskRequest
from app.services.ai_service import AIService
from app.services.risk_service import RiskService

router = APIRouter()


@router.post("/explain/risk", response_model=ExplainResponse)
async def explain_risk(
    payload: ExplainRiskRequest,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ExplainResponse:
    from sqlalchemy import select

    redis = await get_redis()
    cache_key = f"ai:risk_explain:{payload.asset_id}:{payload.requesting_role}"
    cached = await redis.get(cache_key)
    if cached:
        return ExplainResponse(explanation=cached, cached=True)

    asset_result = await db.execute(
        select(Asset).where(Asset.id == payload.asset_id, Asset.tenant_id == user.tenant_id)
    )
    asset = asset_result.scalar_one_or_none()
    if not asset:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Asset not found")

    risk_service = RiskService(db)
    risk_score = await risk_service.get_asset_risk(user.tenant_id, payload.asset_id)

    ai_service = AIService(db)
    explanation = await ai_service.explain_risk_score(
        asset_name=asset.name,
        asset_type=asset.asset_type,
        risk_score=risk_score.risk_score,
        risk_band=risk_score.risk_band,
        top_drivers=risk_score.top_drivers or [],
        requesting_role=payload.requesting_role,
    )

    await redis.set(cache_key, explanation, ex=3600)
    return ExplainResponse(explanation=explanation, cached=False)
