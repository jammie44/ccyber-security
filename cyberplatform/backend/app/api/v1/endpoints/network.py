"""
app/api/v1/endpoints/network.py
Network monitoring, unknown device detection, access anomaly analysis,
and PII protection scanning.
"""
from __future__ import annotations

import logging
import uuid
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import get_db
from app.middleware.auth import CurrentUser, require_role
from app.models.user import UserRole
from app.services.network_monitor_service import (
    scan_for_unknown_devices,
    list_unknown_devices,
    approve_unknown_device,
    analyze_access_patterns,
    scan_for_pii,
    list_pii_findings,
    resolve_pii_finding,
)

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Schemas ───────────────────────────────────────────────────────────────────

class ScanForUnknownsRequest(BaseModel):
    ip_range: str
    fast: bool = True


class UnknownDeviceItem(BaseModel):
    id: str
    ip_address: str
    mac_address: str
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    open_ports: Optional[list] = None
    first_seen: str
    last_seen: str
    alert_id: Optional[str] = None


class ScanForUnknownsResponse(BaseModel):
    unknown_devices_found: int
    alerts_raised: int
    devices: list
    error: Optional[str] = None


class ApproveDeviceResponse(BaseModel):
    id: str
    is_approved: bool
    approved_by: str
    approved_at: str


class AnalyzeAccessResponse(BaseModel):
    anomalies_found: int
    alerts_raised: int
    details: list


class ScanForPiiResponse(BaseModel):
    findings_created: int
    error: Optional[str] = None


class PiiFindingItem(BaseModel):
    id: str
    source_table: str
    source_record_id: str
    source_field: str
    pii_type: str
    pii_sample: str
    severity: str
    detected_at: str


class ResolvePiiResponse(BaseModel):
    id: str
    is_resolved: bool
    resolved_at: str


# ── WiFi Device Monitor ───────────────────────────────────────────────────────

@router.get("/unknown-devices", response_model=list[UnknownDeviceItem])
async def get_unknown_devices(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[UnknownDeviceItem]:
    """Lists all unapproved unknown devices detected on the network."""
    devices = await list_unknown_devices(db, user.tenant_id)
    return [UnknownDeviceItem(**d) for d in devices]


@router.post("/unknown-devices/{device_id}/approve", response_model=ApproveDeviceResponse)
async def approve_device(
    device_id: uuid.UUID,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, require_role(UserRole.SECURITY_MANAGER)] = None,
) -> ApproveDeviceResponse:
    """Marks an unknown device as known/approved. Requires Security Manager role."""
    result = await approve_unknown_device(db, user.tenant_id, device_id, approved_by=user.id)
    if not result:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"Unknown device event {device_id} not found")
    return ApproveDeviceResponse(**result)


@router.post("/scan-for-unknowns", response_model=ScanForUnknownsResponse)
async def trigger_unknown_scan(
    request: ScanForUnknownsRequest,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, require_role(UserRole.SECURITY_MANAGER)] = None,
) -> ScanForUnknownsResponse:
    """
    Runs a live nmap scan of the given IP range and compares results
    against the known asset inventory. Requires network access to the
    target range — use the scanner agent for remote/LAN scanning.
    Requires Security Manager role.
    """
    result = await scan_for_unknown_devices(db, user.tenant_id, request.ip_range, request.fast)
    return ScanForUnknownsResponse(**result)


# ── Access Anomaly Detection ──────────────────────────────────────────────────

@router.post("/analyze-access", response_model=AnalyzeAccessResponse)
async def analyze_access(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, require_role(UserRole.SECURITY_MANAGER)] = None,
) -> AnalyzeAccessResponse:
    """
    Scans the last hour of access logs for impossible travel, bulk data
    harvesting, and privilege probing patterns. Fires Alerts for any
    anomalies found. Requires Security Manager role.
    """
    result = await analyze_access_patterns(db, user.tenant_id)
    return AnalyzeAccessResponse(**result)


# ── PII Protection Scanner ────────────────────────────────────────────────────

@router.post("/scan-for-pii", response_model=ScanForPiiResponse)
async def trigger_pii_scan(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, require_role(UserRole.ANALYST)] = None,
) -> ScanForPiiResponse:
    """
    Scans all asset and vulnerability records for PII patterns (emails,
    phone numbers, credit card numbers, SA IDs, passports). Requires
    Analyst role or above.
    """
    result = await scan_for_pii(db, user.tenant_id)
    return ScanForPiiResponse(**result)


@router.get("/pii-findings", response_model=list[PiiFindingItem])
async def get_pii_findings(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[PiiFindingItem]:
    """Lists all unresolved PII findings for your organization."""
    findings = await list_pii_findings(db, user.tenant_id)
    return [PiiFindingItem(**f) for f in findings]


@router.post("/pii-findings/{finding_id}/resolve", response_model=ResolvePiiResponse)
async def resolve_pii(
    finding_id: uuid.UUID,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, require_role(UserRole.ANALYST)] = None,
) -> ResolvePiiResponse:
    """Marks a PII finding as resolved. Requires Analyst role or above."""
    result = await resolve_pii_finding(db, user.tenant_id, finding_id)
    if not result:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"PII finding {finding_id} not found")
    return ResolvePiiResponse(**result)
