from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset, CriticalityLabel
from app.repositories.asset_repository import AssetRepository
from app.schemas.asset import AssetCreate, AssetUpdate


def _criticality_label(score: float) -> str:
    if score >= 8.5:
        return CriticalityLabel.CRITICAL.value
    if score >= 6.5:
        return CriticalityLabel.HIGH.value
    if score >= 4.0:
        return CriticalityLabel.MEDIUM.value
    return CriticalityLabel.LOW.value


class AssetService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.repo = AssetRepository(db)

    async def create_asset(self, tenant_id: uuid.UUID, payload: AssetCreate) -> Asset:
        asset = Asset(
            tenant_id=tenant_id,
            name=payload.name,
            asset_type=payload.asset_type,
            environment=payload.environment,
            criticality_score=payload.criticality_score,
            criticality_label=_criticality_label(payload.criticality_score),
            business_impact_score=payload.business_impact_score,
            data_classification=payload.data_classification,
            exposure_level=payload.exposure_level,
            is_internet_facing=payload.is_internet_facing,
            is_in_compliance_scope=payload.is_in_compliance_scope,
            ip_addresses=payload.ip_addresses,
            hostnames=payload.hostnames,
            os_name=payload.os_name,
            os_version=payload.os_version,
            cloud_provider=payload.cloud_provider,
            cloud_region=payload.cloud_region,
            cloud_resource_id=payload.cloud_resource_id,
            business_unit=payload.business_unit,
            department=payload.department,
            owner_email=payload.owner_email,
            tags=payload.tags,
            notes=payload.notes,
            discovery_source="manual",
        )
        asset = await self.repo.create(asset)
        await self.repo.commit()
        return asset

    async def get_asset(self, tenant_id: uuid.UUID, asset_id: uuid.UUID) -> Asset:
        asset = await self.repo.get_by_id(tenant_id, asset_id)
        if not asset or asset.is_deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
        return asset

    async def update_asset(self, tenant_id: uuid.UUID, asset_id: uuid.UUID, payload: AssetUpdate) -> Asset:
        asset = await self.get_asset(tenant_id, asset_id)
        data = payload.model_dump(exclude_unset=True)
        if "criticality_score" in data and data["criticality_score"] is not None:
            data["criticality_label"] = _criticality_label(data["criticality_score"])
        asset = await self.repo.update(asset, data)
        await self.repo.commit()
        return asset

    async def delete_asset(self, tenant_id: uuid.UUID, asset_id: uuid.UUID) -> None:
        asset = await self.get_asset(tenant_id, asset_id)
        asset.is_deleted = True
        asset.status = "decommissioned"
        await self.repo.commit()

    async def search_assets(self, tenant_id: uuid.UUID, **kwargs):
        return await self.repo.search(tenant_id, **kwargs)

    async def get_summary(self, tenant_id: uuid.UUID) -> dict:
        return await self.repo.get_summary(tenant_id)
