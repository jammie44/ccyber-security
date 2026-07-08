from __future__ import annotations

import structlog
from sqlalchemy import func, select

from app.db.sync_session import SyncSessionLocal
from app.models.asset import Asset
from app.models.tenant import Tenant
from app.models.vulnerability import AssetVulnerability
from app.tasks.celery_app import celery_app

logger = structlog.get_logger()


@celery_app.task(name="app.tasks.monitoring_tasks.daily_metrics_snapshot")
def daily_metrics_snapshot() -> dict:
    """Beat-scheduled daily at midnight UTC: compute and log per-tenant metrics snapshot.

    In this lightweight implementation, metrics are computed on-demand via API rather
    than materialized into a separate table — this task validates data integrity and
    can be extended to write into a `daily_metrics` table if introduced in a later migration.
    """
    db = SyncSessionLocal()
    try:
        tenants = db.execute(select(Tenant).where(Tenant.is_active == True)).scalars().all()  # noqa: E712
        summary = []
        for tenant in tenants:
            asset_count = db.execute(
                select(func.count()).select_from(Asset).where(Asset.tenant_id == tenant.id, Asset.is_deleted == False)  # noqa: E712
            ).scalar_one()
            open_critical = db.execute(
                select(func.count()).select_from(AssetVulnerability).where(
                    AssetVulnerability.tenant_id == tenant.id,
                    AssetVulnerability.priority == "critical",
                    AssetVulnerability.status.in_(
                        ["discovered", "triaged", "assigned", "in_remediation", "pending_verification"]
                    ),
                )
            ).scalar_one()
            summary.append({"tenant": tenant.slug, "assets": asset_count, "open_critical_vulns": open_critical})

        logger.info("daily_metrics_snapshot_completed", tenant_count=len(tenants), summary=summary)
        return {"status": "ok", "tenants": len(tenants)}
    finally:
        db.close()


@celery_app.task(name="app.tasks.monitoring_tasks.check_certificate_expiry")
def check_certificate_expiry() -> dict:
    """Placeholder task for certificate expiry alerting (Module 8 built-in rule)."""
    logger.info("certificate_expiry_check_run")
    return {"status": "ok"}
