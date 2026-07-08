from __future__ import annotations

import structlog
from sqlalchemy import select

from app.db.sync_session import SyncSessionLocal
from app.models.asset import Asset
from app.models.tenant import Tenant
from app.services.risk_scoring_engine import RiskInput, compute_risk_score
from app.tasks.celery_app import celery_app

logger = structlog.get_logger()


@celery_app.task(name="app.tasks.risk_tasks.recompute_asset_risk_sync")
def recompute_asset_risk_sync(tenant_id: str, asset_id: str) -> dict:
    """Synchronous risk recompute, callable from Celery worker context."""
    from app.models.risk import AssetRiskScore
    import uuid

    db = SyncSessionLocal()
    try:
        asset = db.execute(
            select(Asset).where(Asset.id == uuid.UUID(asset_id), Asset.tenant_id == uuid.UUID(tenant_id))
        ).scalar_one_or_none()
        if not asset:
            return {"status": "asset_not_found"}

        risk_input = RiskInput(
            asset_id=asset_id,
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
        )
        output = compute_risk_score(risk_input)

        row = db.execute(
            select(AssetRiskScore).where(
                AssetRiskScore.asset_id == uuid.UUID(asset_id), AssetRiskScore.tenant_id == uuid.UUID(tenant_id)
            )
        ).scalar_one_or_none()

        if row:
            row.risk_score = output.risk_score
            row.risk_band = output.risk_band
            row.confidence = output.confidence
        else:
            row = AssetRiskScore(
                tenant_id=uuid.UUID(tenant_id),
                asset_id=uuid.UUID(asset_id),
                risk_score=output.risk_score,
                risk_band=output.risk_band,
                confidence=output.confidence,
            )
            db.add(row)

        asset.current_risk_score = output.risk_score
        asset.current_risk_band = output.risk_band

        db.commit()
        logger.info("asset_risk_recomputed", asset_id=asset_id, risk_score=output.risk_score)
        return {"status": "ok", "risk_score": output.risk_score, "risk_band": output.risk_band}
    finally:
        db.close()


@celery_app.task(name="app.tasks.risk_tasks.recompute_all_org_risk_scores")
def recompute_all_org_risk_scores() -> dict:
    """Beat-scheduled: recompute org-level risk score for every tenant."""
    from sqlalchemy import func
    from app.models.risk import AssetRiskScore, OrgRiskScore

    db = SyncSessionLocal()
    processed = 0
    try:
        tenants = db.execute(select(Tenant).where(Tenant.is_active == True)).scalars().all()  # noqa: E712
        for tenant in tenants:
            avg_score, scored_count = db.execute(
                select(func.avg(AssetRiskScore.risk_score), func.count(AssetRiskScore.id)).where(
                    AssetRiskScore.tenant_id == tenant.id
                )
            ).one()
            avg_score = float(avg_score or 0.0)

            band = "minimal"
            if avg_score >= 80:
                band = "critical"
            elif avg_score >= 60:
                band = "high"
            elif avg_score >= 40:
                band = "medium"
            elif avg_score >= 20:
                band = "low"

            org_row = db.execute(
                select(OrgRiskScore).where(OrgRiskScore.tenant_id == tenant.id)
            ).scalar_one_or_none()
            if org_row:
                org_row.risk_score = round(avg_score, 2)
                org_row.risk_band = band
                org_row.assets_assessed = scored_count
            else:
                org_row = OrgRiskScore(
                    tenant_id=tenant.id, risk_score=round(avg_score, 2), risk_band=band, assets_assessed=scored_count
                )
                db.add(org_row)
            processed += 1
        db.commit()
        logger.info("org_risk_recomputed_all_tenants", count=processed)
        return {"status": "ok", "tenants_processed": processed}
    finally:
        db.close()
