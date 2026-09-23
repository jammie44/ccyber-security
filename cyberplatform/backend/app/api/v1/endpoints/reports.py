"""
app/api/v1/endpoints/reports.py

GET  /api/v1/reports/executive-pdf
POST /api/v1/reports/send-digest
GET  /api/v1/reports/compliance-export
GET  /api/v1/reports/history
"""
from __future__ import annotations

import logging
import os
from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import get_db
from app.middleware.auth import CurrentUser, require_role
from app.models.user import UserRole
from app.services.report_service import (
    generate_executive_pdf,
    send_weekly_digest,
    generate_compliance_export,
    get_report_history,
)

logger = logging.getLogger(__name__)
router = APIRouter()

DASHBOARD_URL = os.environ.get("PLATFORM_DASHBOARD_URL", "https://cyberplatform-web.onrender.com/dashboard")


def _cleanup_file(path: str) -> None:
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        logger.exception("Failed to clean up temp file %s", path)


class SendDigestResponse(BaseModel):
    status: str
    recipient_count: int
    reason: Optional[str] = None


class ReportHistoryItem(BaseModel):
    id: str
    report_type: str
    generated_by: Optional[str]
    generated_at: str
    file_size_bytes: Optional[int]
    recipient_count: Optional[int]
    status: str


@router.get("/executive-pdf")
async def get_executive_pdf(
    background_tasks: BackgroundTasks,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, require_role(UserRole.SECURITY_MANAGER)] = None,
) -> FileResponse:
    """
    Generates and downloads the 6-page executive PDF security report.
    Requires Security Manager role or above.
    Includes: cover, executive summary (AI-written if Groq configured),
    asset inventory, top vulnerabilities, simulation findings, remediation roadmap.
    """
    tenant_name = str(user.tenant_id)  # fallback; ideally fetch from Tenant table
    try:
        # Try to get the actual org name
        from sqlalchemy import select
        from app.models.tenant import Tenant
        t = (await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))).scalar_one_or_none()
        if t:
            tenant_name = t.name or str(user.tenant_id)
    except Exception:
        pass

    try:
        pdf_path = await generate_executive_pdf(
            db, user.tenant_id, tenant_name, generated_by=user.id
        )
    except Exception as e:
        logger.exception("Executive PDF generation failed for tenant %s", user.tenant_id)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"PDF generation failed: {e}")

    background_tasks.add_task(_cleanup_file, pdf_path)
    safe_name = tenant_name.replace(" ", "-").lower()
    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=f"executive-security-report-{safe_name}.pdf",
    )


@router.post("/send-digest", response_model=SendDigestResponse)
async def trigger_digest(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, require_role(UserRole.SECURITY_MANAGER)] = None,
) -> SendDigestResponse:
    """
    Manually triggers the weekly digest email immediately.
    Useful for testing SMTP configuration before Monday's scheduled run.
    Requires Security Manager role or above.
    """
    tenant_name = str(user.tenant_id)
    try:
        from sqlalchemy import select
        from app.models.tenant import Tenant
        t = (await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))).scalar_one_or_none()
        if t:
            tenant_name = t.name or str(user.tenant_id)
    except Exception:
        pass

    try:
        result = await send_weekly_digest(db, user.tenant_id, tenant_name, DASHBOARD_URL)
    except Exception as e:
        logger.exception("Manual digest send failed for tenant %s", user.tenant_id)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Digest send failed: {e}")

    return SendDigestResponse(**result)


@router.get("/compliance-export")
async def get_compliance_export(
    background_tasks: BackgroundTasks,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, require_role(UserRole.SECURITY_MANAGER)] = None,
) -> FileResponse:
    """
    Generates and downloads the compliance evidence ZIP.
    Contains JSON evidence files for ISO 27001, SOC 2, and NIST CSF audits.
    Requires Security Manager role or above.
    """
    tenant_name = str(user.tenant_id)
    try:
        from sqlalchemy import select
        from app.models.tenant import Tenant
        t = (await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))).scalar_one_or_none()
        if t:
            tenant_name = t.name or str(user.tenant_id)
    except Exception:
        pass

    try:
        zip_path = await generate_compliance_export(
            db, user.tenant_id, tenant_name, generated_by=user.id
        )
    except Exception as e:
        logger.exception("Compliance export failed for tenant %s", user.tenant_id)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Compliance export failed: {e}")

    background_tasks.add_task(_cleanup_file, zip_path)
    safe_name = tenant_name.replace(" ", "-").lower()
    return FileResponse(
        path=zip_path,
        media_type="application/zip",
        filename=f"compliance-evidence-{safe_name}.zip",
    )


@router.get("/history", response_model=list[ReportHistoryItem])
async def report_history(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[ReportHistoryItem]:
    """Lists the last 50 report generation events for your organization."""
    rows = await get_report_history(db, user.tenant_id, limit=50)
    return [ReportHistoryItem(**r) for r in rows]
