"""
app/api/v1/endpoints/intelligence.py

POST /api/v1/intelligence/briefing
GET  /api/v1/intelligence/predictions
POST /api/v1/intelligence/predictions/recompute
GET  /api/v1/intelligence/trends
POST /api/v1/intelligence/snapshot
POST /api/v1/intelligence/analyze
"""
from __future__ import annotations

import logging
from typing import Annotated, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import get_db
from app.middleware.auth import CurrentUser, require_role
from app.models.user import UserRole
from app.services.intelligence_service import (
    generate_briefing,
    compute_predictions,
    get_predictions,
    get_trends,
    take_snapshot,
    run_anomaly_detection,
)

logger = logging.getLogger(__name__)
router = APIRouter()


class BriefingRequest(BaseModel):
    audience: Literal["executive", "analyst", "owner"]


class BriefingResponse(BaseModel):
    briefing: str
    generated_at: str
    audience: str


class PredictionItem(BaseModel):
    asset_id: str
    asset_name: str
    predicted_severity: str
    confidence_score: float
    prediction_reason: str
    based_on_asset_count: int
    created_at: Optional[str] = None


class TrendMetric(BaseModel):
    current_value: float
    value_7d_ago: Optional[float]
    delta: Optional[float]
    direction: str


class SnapshotResponse(BaseModel):
    status: str
    snapshot_date: Optional[str] = None
    org_risk_score: float
    open_critical_vulns: int
    open_high_vulns: int
    sla_compliance_rate: float
    assets_scanned: int
    assets_with_exposures: int
    total_simulation_findings: int


class AnalyzeResponse(BaseModel):
    anomalies_found: int
    alerts_raised: int
    details: list


@router.post("/briefing", response_model=BriefingResponse)
async def get_briefing(
    request: BriefingRequest,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> BriefingResponse:
    """
    Generates (or returns cached) audience-specific security briefing.
    Uses Groq/Llama if GROQ_API_KEY is set, otherwise falls back to a
    template-based briefing. Cached in Redis for 4 hours.
    """
    try:
        result = await generate_briefing(db, user.tenant_id, request.audience)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.exception("Briefing generation failed for tenant %s", user.tenant_id)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    return BriefingResponse(**result)


@router.get("/predictions", response_model=list[PredictionItem])
async def list_predictions(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[PredictionItem]:
    """Returns stored risk predictions for unscanned assets."""
    try:
        preds = await get_predictions(db, user.tenant_id)
    except Exception as e:
        logger.exception("Failed to fetch predictions")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    return [PredictionItem(**p) for p in preds]


@router.post("/predictions/recompute", response_model=list[PredictionItem])
async def recompute_predictions(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, require_role(UserRole.ANALYST)] = None,
) -> list[PredictionItem]:
    """
    Runs pattern learning against all unscanned assets and writes fresh
    AssetRiskPrediction rows. Requires Analyst role or above.
    """
    try:
        preds = await compute_predictions(db, user.tenant_id)
    except Exception as e:
        logger.exception("Failed to compute predictions")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    return [PredictionItem(**p) for p in preds]


@router.get("/trends", response_model=dict[str, TrendMetric])
async def trends(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, TrendMetric]:
    """Returns current posture metrics with 7-day deltas and direction."""
    try:
        result = await get_trends(db, user.tenant_id)
    except Exception as e:
        logger.exception("Failed to compute trends")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    return {k: TrendMetric(**v) for k, v in result.items()}


@router.post("/snapshot", response_model=SnapshotResponse)
async def snapshot(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, require_role(UserRole.ANALYST)] = None,
) -> SnapshotResponse:
    """
    Saves a snapshot of current posture metrics. Call this after every
    assessment or simulation run so trends and anomaly detection have a
    meaningful baseline. Requires Analyst role or above.
    """
    try:
        result = await take_snapshot(db, user.tenant_id)
    except Exception as e:
        logger.exception("Failed to take snapshot")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    return SnapshotResponse(**result)


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, require_role(UserRole.ANALYST)] = None,
) -> AnalyzeResponse:
    """
    Compares current metrics to the most recent snapshot and fires
    Alerts for significant changes. Requires Analyst role or above.
    """
    try:
        result = await run_anomaly_detection(db, user.tenant_id)
    except Exception as e:
        logger.exception("Anomaly detection failed")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    return AnalyzeResponse(**result)
