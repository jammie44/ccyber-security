"""
assessment.py
FastAPI endpoints for vulnerability assessment.

POST /api/v1/assessment/{asset_id}   — assess one asset
POST /api/v1/assessment/all          — assess all assets for the tenant
"""
from __future__ import annotations

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import get_db
from app.middleware.auth import CurrentUser, require_role
from app.models.user import UserRole
from app.services.vulnerability_scanner.assessment_service import (
    assess_asset,
    assess_all_assets,
    AssetNotFoundError,
)

logger = logging.getLogger(__name__)
router = APIRouter()


class AssessmentResult(BaseModel):
    asset_id: str
    asset_name: str
    port_findings: int
    cve_matches: int
    total_findings: int
    severity_counts: dict


class AssessAllResponse(BaseModel):
    assets_assessed: int
    assets_failed: int
    failures: list
    results: list[AssessmentResult]


@router.post("/{asset_id}", response_model=AssessmentResult)
async def assess_single_asset(
    asset_id: uuid.UUID,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, require_role(UserRole.ANALYST)] = None,
) -> AssessmentResult:
    """
    Runs full vulnerability assessment for one asset:
    - Checks open ports for dangerous/misconfigured services
    - Matches asset OS against CVEs in the NVD database
    - Scores each finding by severity
    - Stores results as AssetVulnerability records
    - Updates the asset's vulnerability counters

    Replaces any previous scanner-generated findings for this asset.
    Manually-added findings are preserved.
    """
    try:
        result = await assess_asset(db, user.tenant_id, asset_id)
    except AssetNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset {asset_id} not found",
        )
    except Exception as exc:
        logger.exception("Assessment failed for asset %s", asset_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Assessment failed: {exc}",
        )

    return AssessmentResult(**result)


@router.post("/all", response_model=AssessAllResponse)
async def assess_all(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, require_role(UserRole.SECURITY_MANAGER)] = None,
) -> AssessAllResponse:
    """
    Runs vulnerability assessment across ALL active assets for your
    organization. This can take several seconds for large inventories.

    Requires Security Manager role or above.
    """
    result = await assess_all_assets(db, user.tenant_id)
    return AssessAllResponse(**result)
