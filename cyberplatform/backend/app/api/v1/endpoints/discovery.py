"""
discovery.py
FastAPI endpoints for network device discovery.

POST /api/v1/discovery/scan   - Triggers nmap scan from this server
                                (only works when server has LAN access)
POST /api/v1/discovery/ingest - Accepts results from an on-prem agent
                                (works from Render — agent scans locally
                                 and POSTs results here)
GET  /api/v1/discovery/status - Check if nmap is available on this host
"""
from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import get_db
from app.middleware.auth import CurrentUser, require_role
from app.models.user import UserRole
from app.services.discovery.schemas import IngestRequest, ScanRequest, ScanResponse
from app.services.discovery.asset_persistence import upsert_assets_from_scan
from app.services.discovery.scanner_service import ScannerError, get_scanner, is_nmap_available

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/status")
async def discovery_status(user: CurrentUser) -> dict:
    """
    Returns whether nmap is installed and available on this host.
    Use this to check if direct scanning will work from the server.
    """
    available = is_nmap_available()
    return {
        "nmap_available": available,
        "message": (
            "nmap is installed — direct scanning available."
            if available else
            "nmap is not installed on this server. Use the on-prem agent "
            "(POST /api/v1/discovery/ingest) to scan your local network."
        ),
    }


@router.post("/scan", response_model=ScanResponse)
async def scan_network(
    request: ScanRequest,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, require_role(UserRole.SECURITY_MANAGER)] = None,
) -> ScanResponse:
    """
    Triggers an nmap scan of the given IP range from this server.

    IMPORTANT: This only works when the server has direct network access
    to the target range. On Render.com free tier this will NOT reach
    private LAN ranges (192.168.x.x). Use POST /ingest with the
    on-premises agent instead.

    Requires Security Manager role or above.
    """
    if not is_nmap_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "nmap is not installed on this server. "
                "Use the on-premises agent and POST results to /api/v1/discovery/ingest instead. "
                "See the agent script in the repository at agent/scanner_agent.py"
            ),
        )

    try:
        scanner = get_scanner()
        devices, duration = scanner.scan(
            ip_range=request.ip_range,
            ports=request.ports or "21-23,25,53,80,443,445,3306,3389,8080,8443",
            fast=request.fast,
        )
    except ScannerError as exc:
        logger.exception("Discovery scan failed for %s", request.ip_range)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        )

    created, updated = await upsert_assets_from_scan(db, user.tenant_id, devices)

    return ScanResponse(
        ip_range=request.ip_range,
        devices_found=len(devices),
        devices=devices,
        scan_duration_seconds=round(duration, 2),
        assets_created=created,
        assets_updated=updated,
    )


@router.post("/ingest", response_model=ScanResponse)
async def ingest_scan_results(
    request: IngestRequest,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, require_role(UserRole.ANALYST)] = None,
) -> ScanResponse:
    """
    Accepts scan results POSTed from an on-premises agent.

    The agent runs on a machine inside the target network, scans locally
    using nmap, and sends the results here. This is the recommended approach
    for Render deployments that cannot reach private LAN ranges directly.

    The agent script is at: agent/scanner_agent.py in the repository.
    Run it with: python scanner_agent.py --range 192.168.1.0/24 --api-url https://your-api.onrender.com --token YOUR_JWT_TOKEN

    Requires Analyst role or above.
    """
    created, updated = await upsert_assets_from_scan(
        db, user.tenant_id, request.devices
    )

    return ScanResponse(
        ip_range=request.ip_range,
        devices_found=len(request.devices),
        devices=request.devices,
        scan_duration_seconds=request.scan_duration_seconds,
        assets_created=created,
        assets_updated=updated,
    )
