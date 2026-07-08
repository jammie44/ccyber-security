from __future__ import annotations

import uuid
from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import get_db
from app.middleware.auth import CurrentUser
from app.schemas.vulnerability import (
    AssetVulnerabilityCreate,
    AssetVulnerabilityOut,
    AssetVulnerabilityUpdate,
    VulnerabilityListResponse,
    VulnerabilitySummary,
)
from app.services.vulnerability_service import VulnerabilityService

router = APIRouter()


@router.get("", response_model=VulnerabilityListResponse)
async def list_vulnerabilities(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    status: Optional[List[str]] = Query(default=None),
    priority: Optional[List[str]] = Query(default=None),
    asset_id: Optional[uuid.UUID] = None,
    sla_status: Optional[str] = None,
    page: int = 1,
    per_page: int = 50,
) -> VulnerabilityListResponse:
    service = VulnerabilityService(db)
    items, total = await service.search_findings(
        user.tenant_id,
        status=status,
        priority=priority,
        asset_id=asset_id,
        sla_status=sla_status,
        page=page,
        per_page=per_page,
    )
    return VulnerabilityListResponse(
        vulnerabilities=[AssetVulnerabilityOut.model_validate(v) for v in items],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/summary", response_model=VulnerabilitySummary)
async def get_vulnerability_summary(
    user: CurrentUser, db: Annotated[AsyncSession, Depends(get_db)]
) -> VulnerabilitySummary:
    service = VulnerabilityService(db)
    data = await service.get_summary(user.tenant_id)
    return VulnerabilitySummary(**data)


@router.post("", response_model=AssetVulnerabilityOut, status_code=201)
async def create_vulnerability_finding(
    payload: AssetVulnerabilityCreate,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AssetVulnerabilityOut:
    service = VulnerabilityService(db)
    finding = await service.create_finding(user.tenant_id, payload)
    return AssetVulnerabilityOut.model_validate(finding)


@router.get("/{finding_id}", response_model=AssetVulnerabilityOut)
async def get_vulnerability_finding(
    finding_id: uuid.UUID,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AssetVulnerabilityOut:
    service = VulnerabilityService(db)
    finding = await service.get_finding(user.tenant_id, finding_id)
    return AssetVulnerabilityOut.model_validate(finding)


@router.patch("/{finding_id}", response_model=AssetVulnerabilityOut)
async def update_vulnerability_finding(
    finding_id: uuid.UUID,
    payload: AssetVulnerabilityUpdate,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AssetVulnerabilityOut:
    service = VulnerabilityService(db)
    finding = await service.update_finding(user.tenant_id, finding_id, payload)
    return AssetVulnerabilityOut.model_validate(finding)
