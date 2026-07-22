"""
simulation_service.py
Orchestrates web probing + network exposure validation for an asset,
persists AttackSimulationResult rows, and raises Alerts on confirmed
high/critical findings.

Uses the existing Alert and Asset models from the platform.
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.alert import Alert, AlertStatus, AlertSeverity
from app.models.attack_simulation_result import AttackSimulationResult, SimulationType

from .web_probe import probe_web_service
from .exposure_check import validate_exposure

logger = logging.getLogger(__name__)


class AssetNotFoundError(Exception):
    pass


def _primary_ip(asset: Asset) -> Optional[str]:
    if not asset.ip_addresses:
        return None
    if isinstance(asset.ip_addresses, list):
        return asset.ip_addresses[0] if asset.ip_addresses else None
    return str(asset.ip_addresses)


def _open_ports(asset: Asset) -> list[dict]:
    if not asset.custom_attributes:
        return []
    return asset.custom_attributes.get("open_ports", []) or []


def _make_fingerprint(asset_id: uuid.UUID, sim_type: str, port: Optional[int], title: str) -> str:
    raw = f"sim:{asset_id}:{sim_type}:{port}:{title}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


async def _persist_finding(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    asset: Asset,
    simulation_type: str,
    finding,
) -> AttackSimulationResult:
    row = AttackSimulationResult(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        asset_id=asset.id,
        simulation_type=simulation_type,
        target_port=finding.target_port,
        finding_title=finding.finding_title,
        finding_detail=finding.finding_detail,
        severity=finding.severity,
        was_successful=finding.was_successful,
        context_data=finding.context_data,
        simulated_at=datetime.now(timezone.utc),
    )
    db.add(row)
    return row


async def _maybe_raise_alert(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    asset: Asset,
    result: AttackSimulationResult,
) -> Optional[Alert]:
    """
    Fires an Alert for confirmed (was_successful=True) high or critical
    findings. Uses fingerprint dedup so repeated simulations don't
    create duplicate open alerts.
    """
    if not (result.was_successful and result.severity in ("critical", "high")):
        return None

    asset_name = getattr(asset, "name", None) or str(asset.id)
    fingerprint = _make_fingerprint(
        asset.id, result.simulation_type, result.target_port, result.finding_title
    )

    # Check if an open alert with this fingerprint already exists
    existing = await db.execute(
        select(Alert).where(
            Alert.tenant_id == tenant_id,
            Alert.fingerprint == fingerprint,
            Alert.status == AlertStatus.OPEN.value,
        )
    )
    if existing.scalar_one_or_none():
        return None  # already alerted, skip duplicate

    alert = Alert(
        tenant_id=tenant_id,
        rule_id=None,
        title=f"{result.severity.upper()}: {result.finding_title} on {asset_name}",
        message=result.finding_detail,
        severity=AlertSeverity.CRITICAL.value if result.severity == "critical" else AlertSeverity.HIGH.value,
        status=AlertStatus.OPEN.value,
        fingerprint=fingerprint,
        asset_id=asset.id,
        asset_name=asset_name,
        context_data=result.context_data,
        triggered_at=datetime.now(timezone.utc).isoformat(),
    )
    db.add(alert)
    return alert


async def simulate_asset(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    asset_id: uuid.UUID,
) -> dict:
    """Full simulation pipeline for one asset."""
    result = await db.execute(
        select(Asset).where(
            Asset.id == asset_id,
            Asset.tenant_id == tenant_id,
            Asset.is_deleted == False,  # noqa: E712
        )
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise AssetNotFoundError(f"Asset {asset_id} not found for tenant {tenant_id}")

    host = _primary_ip(asset)
    open_ports = _open_ports(asset)
    open_port_numbers = [p["port"] for p in open_ports]

    all_findings: list[tuple[str, object]] = []

    # Web probing (ports 80 / 443)
    for port_entry in open_ports:
        port = port_entry["port"]
        if port not in (80, 443):
            continue
        try:
            web_findings = await probe_web_service(host, port)
            all_findings.extend((SimulationType.WEB_PROBE.value, f) for f in web_findings)
        except Exception:
            logger.exception("Web probe failed for asset %s port %s", asset_id, port)

    # Network exposure validation
    if host:
        try:
            exposure_findings = await validate_exposure(
                host,
                open_port_numbers,
                bool(getattr(asset, "is_internet_facing", False)),
            )
            all_findings.extend(
                (SimulationType.EXPOSURE_CHECK.value, f) for f in exposure_findings
            )
        except Exception:
            logger.exception("Exposure validation failed for asset %s", asset_id)

    # Persist findings
    persisted: list[AttackSimulationResult] = []
    for sim_type, finding in all_findings:
        try:
            row = await _persist_finding(db, tenant_id, asset, sim_type, finding)
            persisted.append(row)
        except Exception:
            logger.exception("Failed to persist finding for asset %s", asset_id)

    await db.flush()

    # Raise alerts for confirmed high/critical findings
    alerts_raised = 0
    for row in persisted:
        try:
            alert = await _maybe_raise_alert(db, tenant_id, asset, row)
            if alert is not None:
                alerts_raised += 1
        except Exception:
            logger.exception("Failed to raise alert for finding on asset %s", asset_id)

    await db.commit()

    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for row in persisted:
        severity_counts[row.severity] = severity_counts.get(row.severity, 0) + 1

    logger.info(
        "Simulation complete for asset %s: %d findings, %d alerts raised",
        asset_id, len(persisted), alerts_raised,
    )

    return {
        "asset_id": str(asset_id),
        "asset_name": asset.name,
        "findings": len(persisted),
        "alerts_raised": alerts_raised,
        "severity_counts": severity_counts,
    }


async def simulate_all_assets(
    db: AsyncSession,
    tenant_id: uuid.UUID,
) -> dict:
    """Runs simulate_asset() across all active assets for the tenant."""
    result = await db.execute(
        select(Asset.id).where(
            Asset.tenant_id == tenant_id,
            Asset.is_deleted == False,  # noqa: E712
        )
    )
    asset_ids = [row[0] for row in result.all()]

    summaries, failures = [], []
    for aid in asset_ids:
        try:
            summary = await simulate_asset(db, tenant_id, aid)
            summaries.append(summary)
        except Exception as exc:
            logger.exception("Simulation failed for asset %s", aid)
            failures.append({"asset_id": str(aid), "error": str(exc)})

    return {
        "assets_simulated": len(summaries),
        "assets_failed": len(failures),
        "failures": failures,
        "results": summaries,
    }
