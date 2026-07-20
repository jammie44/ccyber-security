"""
asset_persistence.py
Bridges scan results -> the existing Asset table.

Uses the real Asset SQLAlchemy model from app.models.asset.
Matches devices by MAC address first, then IP address.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Tuple

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.asset import Asset, AssetType, AssetStatus, ExposureLevel
from .schemas import DiscoveredDevice


def _guess_asset_type(device: DiscoveredDevice) -> str:
    """Infer asset type from open ports and OS information."""
    ports = {p.port for p in device.open_ports}
    os_lower = (device.os_name or "").lower()

    if 3389 in ports or "windows" in os_lower:
        return AssetType.WORKSTATION.value
    if 22 in ports and (80 in ports or 443 in ports):
        return AssetType.PHYSICAL_SERVER.value
    if 3306 in ports or 5432 in ports or 1433 in ports:
        return AssetType.DATABASE.value
    if 80 in ports or 443 in ports or 8080 in ports or 8443 in ports:
        return AssetType.WEB_APPLICATION.value
    if any(p in ports for p in (161, 162, 179, 520)):
        return AssetType.NETWORK_DEVICE.value
    return AssetType.OTHER.value


def _build_asset_name(device: DiscoveredDevice) -> str:
    """Build a human-readable asset name from discovery data."""
    if device.hostname:
        return device.hostname
    if device.vendor:
        return f"{device.vendor} device ({device.ip_address})"
    return f"Device {device.ip_address}"


async def upsert_assets_from_scan(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    devices: List[DiscoveredDevice],
) -> Tuple[int, int]:
    """
    Inserts new Asset rows or updates existing ones for the given tenant.
    Match priority: MAC address > IP address.
    Returns (created_count, updated_count).
    """
    created = updated = 0

    for device in devices:
        existing = None

        # Try MAC address match first (survives DHCP lease changes)
        if device.mac_address:
            result = await db.execute(
                select(Asset).where(
                    Asset.tenant_id == tenant_id,
                    Asset.ip_addresses.contains([device.mac_address]),
                )
            )
            # MAC stored in ip_addresses JSONB — try a direct name search instead
            # Search by hostname or check custom_attributes for mac
            result2 = await db.execute(
                select(Asset).where(
                    Asset.tenant_id == tenant_id,
                    Asset.custom_attributes["mac_address"].as_string() == device.mac_address,
                )
            )
            existing = result2.scalar_one_or_none()

        # Fall back to IP address match
        if existing is None:
            result = await db.execute(
                select(Asset).where(
                    Asset.tenant_id == tenant_id,
                    Asset.ip_addresses.contains([device.ip_address]),
                )
            )
            existing = result.scalar_one_or_none()

        open_ports_summary = [
            {"port": p.port, "protocol": p.protocol, "service": p.service}
            for p in device.open_ports
        ]

        now_iso = datetime.now(timezone.utc).isoformat()

        if existing:
            # Update existing asset with fresh scan data
            existing.ip_addresses = [device.ip_address]
            if device.hostname:
                existing.fqdn = device.hostname
                existing.name = device.hostname
            if device.os_name:
                existing.os_name = device.os_name
            existing.last_scan_date = now_iso
            existing.agent_last_checkin = now_iso
            existing.custom_attributes = {
                **(existing.custom_attributes or {}),
                "mac_address": device.mac_address,
                "vendor": device.vendor,
                "os_accuracy": device.os_accuracy,
                "open_ports": open_ports_summary,
                "last_scan_method": "nmap",
            }
            updated += 1
        else:
            # Create new asset from scan data
            asset_name = _build_asset_name(device)
            asset_type = _guess_asset_type(device)

            # Determine exposure: if it has a public-ish setup, mark as internet
            is_internet = device.ip_address.startswith(("1.", "2.", "3.", "4.", "5.")) or \
                not any(device.ip_address.startswith(p) for p in
                        ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                         "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                         "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                         "172.30.", "172.31.", "192.168.", "127."))

            new_asset = Asset(
                tenant_id=tenant_id,
                name=asset_name,
                asset_type=asset_type,
                status=AssetStatus.ACTIVE.value,
                ip_addresses=[device.ip_address],
                hostnames=[device.hostname] if device.hostname else None,
                fqdn=device.hostname,
                os_name=device.os_name,
                environment="production",
                criticality_score=5.0,
                criticality_label="medium",
                business_impact_score=5.0,
                data_classification="internal",
                exposure_level=ExposureLevel.INTERNET.value if is_internet else ExposureLevel.INTERNAL.value,
                is_internet_facing=is_internet,
                discovery_source="nmap_scan",
                last_scan_date=now_iso,
                agent_last_checkin=now_iso,
                security_health_score=70.0,
                custom_attributes={
                    "mac_address": device.mac_address,
                    "vendor": device.vendor,
                    "os_accuracy": device.os_accuracy,
                    "open_ports": open_ports_summary,
                    "last_scan_method": "nmap",
                },
            )
            db.add(new_asset)
            created += 1

    await db.commit()
    return created, updated
