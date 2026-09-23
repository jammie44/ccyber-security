from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.logging import logger, setup_logging
from app.db.base import AsyncSessionLocal
from app.db.redis_client import close_redis


def start_scheduler():
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        from apscheduler.triggers.interval import IntervalTrigger
        import atexit

        scheduler = BackgroundScheduler()

        def refresh_sla():
            try:
                from app.db.sync_session import SyncSessionLocal
                from app.models.vulnerability import AssetVulnerability
                from sqlalchemy import select
                from datetime import datetime, timezone

                db = SyncSessionLocal()
                OPEN_STATUSES = [
                    "discovered", "triaged", "assigned",
                    "in_remediation", "pending_verification",
                ]
                now = datetime.now(timezone.utc)
                findings = db.execute(
                    select(AssetVulnerability).where(
                        AssetVulnerability.status.in_(OPEN_STATUSES),
                        AssetVulnerability.sla_deadline.is_not(None),
                    )
                ).scalars().all()
                updated = 0
                for f in findings:
                    try:
                        deadline = datetime.fromisoformat(f.sla_deadline)
                    except (TypeError, ValueError):
                        continue
                    days_remaining = (deadline - now).days
                    new_status = (
                        "breached" if days_remaining < 0
                        else "at_risk" if days_remaining <= 2
                        else "on_track"
                    )
                    if new_status != f.sla_status:
                        f.sla_status = new_status
                        updated += 1
                db.commit()
                db.close()
                logger.info("sla_refresh_completed", updated=updated)
            except Exception as e:
                logger.error("sla_refresh_failed", error=str(e))

        def recompute_org_risk():
            try:
                from app.db.sync_session import SyncSessionLocal
                from app.models.risk import AssetRiskScore, OrgRiskScore
                from app.models.tenant import Tenant
                from sqlalchemy import func, select

                db = SyncSessionLocal()
                tenants = db.execute(
                    select(Tenant).where(Tenant.is_active == True)
                ).scalars().all()
                for tenant in tenants:
                    avg_score, count = db.execute(
                        select(
                            func.avg(AssetRiskScore.risk_score),
                            func.count(AssetRiskScore.id),
                        ).where(AssetRiskScore.tenant_id == tenant.id)
                    ).one()
                    avg_score = float(avg_score or 0.0)
                    band = (
                        "critical" if avg_score >= 80
                        else "high" if avg_score >= 60
                        else "medium" if avg_score >= 40
                        else "low" if avg_score >= 20
                        else "minimal"
                    )
                    org_row = db.execute(
                        select(OrgRiskScore).where(OrgRiskScore.tenant_id == tenant.id)
                    ).scalar_one_or_none()
                    if org_row:
                        org_row.risk_score = round(avg_score, 2)
                        org_row.risk_band = band
                        org_row.assets_assessed = count
                    else:
                        org_row = OrgRiskScore(
                            tenant_id=tenant.id,
                            risk_score=round(avg_score, 2),
                            risk_band=band,
                            assets_assessed=count,
                        )
                        db.add(org_row)
                db.commit()
                db.close()
                logger.info("org_risk_recomputed")
            except Exception as e:
                logger.error("org_risk_recompute_failed", error=str(e))

        scheduler.add_job(
            refresh_sla,
            trigger=IntervalTrigger(minutes=15),
            id="refresh_sla",
            replace_existing=True,
        )
        scheduler.add_job(
            recompute_org_risk,
            trigger=IntervalTrigger(hours=1),
            id="recompute_org_risk",
            replace_existing=True,
        )

        # Weekly email digest — every Monday at 08:00 UTC
        # Note: APScheduler uses server local time (UTC on Render).
        # If your customers are in a different timezone, adjust hour accordingly.
        async def run_weekly_digest():
            import os
            dashboard_url = os.environ.get(
                "PLATFORM_DASHBOARD_URL",
                "https://cyberplatform-web.onrender.com/dashboard",
            )
            try:
                from app.db.base import AsyncSessionLocal
                from app.models.tenant import Tenant
                from app.services.report_service import send_weekly_digest
                from sqlalchemy import select

                async with AsyncSessionLocal() as db:
                    try:
                        tenants = (await db.execute(
                            select(Tenant.id, Tenant.name).where(Tenant.is_active == True)  # noqa: E712
                        )).all()
                    except Exception:
                        logger.exception("Weekly digest: failed to fetch tenants")
                        return

                for tenant_id, tenant_name in tenants:
                    async with AsyncSessionLocal() as db:
                        try:
                            result = await send_weekly_digest(db, tenant_id, tenant_name or str(tenant_id), dashboard_url)
                            logger.info("Weekly digest tenant %s: %s", tenant_id, result)
                        except Exception:
                            logger.exception("Weekly digest failed for tenant %s", tenant_id)
            except Exception:
                logger.exception("Weekly digest job failed entirely")

        import asyncio as _asyncio

        def _weekly_digest_sync():
            """Sync wrapper so APScheduler BackgroundScheduler can call async code."""
            try:
                loop = _asyncio.get_event_loop()
            except RuntimeError:
                loop = _asyncio.new_event_loop()
                _asyncio.set_event_loop(loop)
            loop.run_until_complete(run_weekly_digest())

        from apscheduler.triggers.cron import CronTrigger
        scheduler.add_job(
            _weekly_digest_sync,
            trigger=CronTrigger(day_of_week="mon", hour=8, minute=0),
            id="weekly_security_digest",
            replace_existing=True,
        )

        scheduler.start()
        atexit.register(lambda: scheduler.shutdown())
        logger.info("scheduler_started")

    except Exception as e:
        logger.warning("scheduler_start_failed", error=str(e))


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    logger.info("starting_application", environment=settings.ENVIRONMENT)
    if settings.ENVIRONMENT == "production":
        start_scheduler()
    yield
    await close_redis()
    logger.info("shutting_down_application")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Access Audit Logger (best-effort — never blocks requests)
try:
    from app.middleware.access_logger import AccessLoggerMiddleware
    app.add_middleware(AccessLoggerMiddleware, session_factory=AsyncSessionLocal)
    logger.info("access_logger_middleware_registered")
except Exception as _exc:
    logger.warning("access_logger_middleware_skipped", error=str(_exc))


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Request validation failed",
                "details": exc.errors(),
            }
        },
    )


@app.get("/")
async def root():
    return {
        "service": settings.PROJECT_NAME,
        "status": "running",
        "docs": f"{settings.API_V1_STR}/docs",
    }


app.include_router(api_router, prefix=settings.API_V1_STR)
