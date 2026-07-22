"""
simulate.py
FastAPI endpoints for attack simulation.

POST /api/v1/simulate/{asset_id}  — simulate one asset
POST /api/v1/simulate/all         — simulate all tenant assets
GET  /api/v1/simulate/results     — list simulation results
"""
from __future__ import annotations

import logging
import uuid
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import get_db
from app.middleware.auth import CurrentUser, require_role
from app.models.user import UserRole
from app.models.attack_simulation_result import AttackSimulationResult
from app.services.attack_simulation.simulation_service import (
    simulate_asset,
    simulate_all_assets,
    AssetNotFoundError,
)

logger = logging.getLogger(__name__)
router = APIRouter()


class SimulationResultResponse(BaseModel):
    asset_id: str
    asset_name: str
    findings: int
    alerts_raised: int
    severity_counts: dict


class SimulateAllResponse(BaseModel):
    assets_simulated: int
    assets_failed: int
    failures: list
    results: list[SimulationResultResponse]


class SimulationResultItem(BaseModel):
    id: str
    asset_id: str
    simulation_type: str
    target_port: Optional[int]
    finding_title: str
    finding_detail: str
    severity: str
    was_successful: bool
    simulated_at: str

    model_config = {"from_attributes": True}


@router.post("/{asset_id}", response_model=SimulationResultResponse)
async def simulate_one_asset(
    asset_id: uuid.UUID,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, require_role(UserRole.ANALYST)] = None,
) -> SimulationResultResponse:
    """
    Runs web-probe and network-exposure-validation checks for one asset.
    Writes AttackSimulationResult rows and raises Alerts for confirmed
    high/critical findings. Requires Analyst role or above.
    """
    try:
        result = await simulate_asset(db, user.tenant_id, asset_id)
    except AssetNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"Asset {asset_id} not found")
    except Exception as exc:
        logger.exception("Simulation failed for asset %s", asset_id)
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Simulation failed: {exc}"
        )
    return SimulationResultResponse(**result)


@router.post("/all", response_model=SimulateAllResponse)
async def simulate_all(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, require_role(UserRole.SECURITY_MANAGER)] = None,
) -> SimulateAllResponse:
    """
    Runs simulation across ALL active assets for the organization.
    Requires Security Manager role or above.
    """
    result = await simulate_all_assets(db, user.tenant_id)
    return SimulateAllResponse(**result)


@router.get("/results", response_model=list[SimulationResultItem])
async def list_results(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    asset_id: Optional[uuid.UUID] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    was_successful: Optional[bool] = Query(default=None),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[SimulationResultItem]:
    """Lists simulation results for your organization with optional filters."""
    stmt = select(AttackSimulationResult).where(
        AttackSimulationResult.tenant_id == user.tenant_id
    )
    if asset_id:
        stmt = stmt.where(AttackSimulationResult.asset_id == asset_id)
    if severity:
        stmt = stmt.where(AttackSimulationResult.severity == severity)
    if was_successful is not None:
        stmt = stmt.where(AttackSimulationResult.was_successful == was_successful)

    stmt = stmt.order_by(AttackSimulationResult.simulated_at.desc()).limit(limit).offset(offset)
    result = await db.execute(stmt)
    rows = result.scalars().all()

    return [
        SimulationResultItem(
            id=str(r.id),
            asset_id=str(r.asset_id),
            simulation_type=r.simulation_type,
            target_port=r.target_port,
            finding_title=r.finding_title,
            finding_detail=r.finding_detail,
            severity=r.severity,
            was_successful=r.was_successful,
            simulated_at=r.simulated_at.isoformat(),
        )
        for r in rows
    ]
