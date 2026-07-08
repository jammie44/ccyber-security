from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.risk import AssetRiskScore, OrgRiskScore, RiskWeightConfig
from app.services.risk_scoring_engine import RiskInput, compute_risk_score, DEFAULT_WEIGHTS


class RiskService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _get_active_weights(self, tenant_id: uuid.UUID) -> dict:
        result = await self.db.execute(
            select(RiskWeightConfig).where(
                RiskWeightConfig.tenant_id == tenant_id,
                RiskWeightConfig.is_active == True,  # noqa: E712
            )
        )
        config = result.scalar_one_or_none()
        if not config:
            return DEFAULT_WEIGHTS
        return {
            "vulnerability": config.vuln_weight,
            "exposure": config.exposure_weight,
            "business": config.business_weight,
            "posture": config.posture_weight,
            "blast_radius": config.blast_radius_weight,
        }

    async def compute_and_store_asset_risk(self, tenant_id: uuid.UUID, asset_id: uuid.UUID) -> AssetRiskScore:
        asset_result = await self.db.execute(
            select(Asset).where(Asset.id == asset_id, Asset.tenant_id == tenant_id)
        )
        asset = asset_result.scalar_one_or_none()
        if not asset:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

        weights = await self._get_active_weights(tenant_id)

        risk_input = RiskInput(
            asset_id=str(asset_id),
            criticality_score=asset.criticality_score,
            business_impact_score=asset.business_impact_score,
            data_classification=asset.data_classification,
            exposure_level=asset.exposure_level,
            is_in_compliance_scope=asset.is_in_compliance_scope,
            is_internet_facing=asset.is_internet_facing,
            security_health_score=asset.security_health_score,
            vuln_count_critical=asset.open_vuln_critical,
            vuln_count_high=asset.open_vuln_high,
            vuln_count_medium=asset.open_vuln_medium,
            vuln_count_low=asset.open_vuln_low,
            last_assessment_age_days=(
                None if not asset.last_scan_date else
                (datetime.now(timezone.utc) - datetime.fromisoformat(asset.last_scan_date)).days
            ),
        )

        output = compute_risk_score(risk_input, weights)

        existing_result = await self.db.execute(
            select(AssetRiskScore).where(AssetRiskScore.asset_id == asset_id, AssetRiskScore.tenant_id == tenant_id)
        )
        existing = existing_result.scalar_one_or_none()

        score_delta = None
        if existing:
            score_delta = round(output.risk_score - existing.risk_score, 2)
            existing.risk_score = output.risk_score
            existing.risk_band = output.risk_band
            existing.confidence = output.confidence
            existing.score_delta = score_delta
            existing.formula_version = output.formula_version
            existing.vuln_score = output.components["vulnerability"].score
            existing.vuln_contribution = output.components["vulnerability"].contribution
            existing.exposure_score = output.components["exposure"].score
            existing.exposure_contribution = output.components["exposure"].contribution
            existing.business_score = output.components["business"].score
            existing.business_contribution = output.components["business"].contribution
            existing.posture_score = output.components["posture"].score
            existing.posture_contribution = output.components["posture"].contribution
            existing.blast_radius_score = output.components["blast_radius"].score
            existing.blast_radius_contribution = output.components["blast_radius"].contribution
            existing.top_drivers = self._top_drivers(output)
            row = existing
        else:
            row = AssetRiskScore(
                tenant_id=tenant_id,
                asset_id=asset_id,
                risk_score=output.risk_score,
                risk_band=output.risk_band,
                confidence=output.confidence,
                formula_version=output.formula_version,
                vuln_score=output.components["vulnerability"].score,
                vuln_contribution=output.components["vulnerability"].contribution,
                exposure_score=output.components["exposure"].score,
                exposure_contribution=output.components["exposure"].contribution,
                business_score=output.components["business"].score,
                business_contribution=output.components["business"].contribution,
                posture_score=output.components["posture"].score,
                posture_contribution=output.components["posture"].contribution,
                blast_radius_score=output.components["blast_radius"].score,
                blast_radius_contribution=output.components["blast_radius"].contribution,
                top_drivers=self._top_drivers(output),
            )
            self.db.add(row)

        # Denormalize onto asset for fast list queries
        asset.current_risk_score = output.risk_score
        asset.current_risk_band = output.risk_band

        await self.db.commit()
        await self.db.refresh(row)
        return row

    def _top_drivers(self, output) -> list[str]:
        all_drivers = []
        for comp in sorted(output.components.values(), key=lambda c: c.contribution, reverse=True):
            for d in comp.drivers[:1]:
                all_drivers.append(d["detail"])
        return all_drivers[:3]

    async def get_asset_risk(self, tenant_id: uuid.UUID, asset_id: uuid.UUID) -> AssetRiskScore:
        result = await self.db.execute(
            select(AssetRiskScore).where(AssetRiskScore.asset_id == asset_id, AssetRiskScore.tenant_id == tenant_id)
        )
        row = result.scalar_one_or_none()
        if not row:
            # Compute on-demand if never scored
            row = await self.compute_and_store_asset_risk(tenant_id, asset_id)
        return row

    async def recompute_org_risk(self, tenant_id: uuid.UUID) -> OrgRiskScore:
        # Weighted average by criticality across all active assets
        result = await self.db.execute(
            select(
                func.avg(AssetRiskScore.risk_score),
                func.count(AssetRiskScore.id),
            ).where(AssetRiskScore.tenant_id == tenant_id)
        )
        avg_score, scored_count = result.one()
        avg_score = float(avg_score or 0.0)

        total_assets_result = await self.db.execute(
            select(func.count()).select_from(Asset).where(Asset.tenant_id == tenant_id, Asset.is_deleted == False)  # noqa: E712
        )
        total_assets = total_assets_result.scalar_one()

        critical_count_result = await self.db.execute(
            select(func.count()).select_from(AssetRiskScore).where(
                AssetRiskScore.tenant_id == tenant_id, AssetRiskScore.risk_band == "critical"
            )
        )
        critical_count = critical_count_result.scalar_one()

        high_count_result = await self.db.execute(
            select(func.count()).select_from(AssetRiskScore).where(
                AssetRiskScore.tenant_id == tenant_id, AssetRiskScore.risk_band == "high"
            )
        )
        high_count = high_count_result.scalar_one()

        band = "minimal"
        if avg_score >= 80:
            band = "critical"
        elif avg_score >= 60:
            band = "high"
        elif avg_score >= 40:
            band = "medium"
        elif avg_score >= 20:
            band = "low"

        result = await self.db.execute(select(OrgRiskScore).where(OrgRiskScore.tenant_id == tenant_id))
        org_row = result.scalar_one_or_none()
        if org_row:
            org_row.risk_score = round(avg_score, 2)
            org_row.risk_band = band
            org_row.assets_assessed = scored_count
            org_row.assets_total = total_assets
            org_row.critical_assets = critical_count
            org_row.high_risk_assets = high_count
        else:
            org_row = OrgRiskScore(
                tenant_id=tenant_id,
                risk_score=round(avg_score, 2),
                risk_band=band,
                assets_assessed=scored_count,
                assets_total=total_assets,
                critical_assets=critical_count,
                high_risk_assets=high_count,
            )
            self.db.add(org_row)

        await self.db.commit()
        await self.db.refresh(org_row)
        return org_row

    async def get_org_risk(self, tenant_id: uuid.UUID) -> OrgRiskScore:
        result = await self.db.execute(select(OrgRiskScore).where(OrgRiskScore.tenant_id == tenant_id))
        row = result.scalar_one_or_none()
        if not row:
            row = await self.recompute_org_risk(tenant_id)
        return row
