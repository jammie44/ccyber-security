"""
app/services/network_monitor_service.py
Three responsibilities:
  1. WiFi device monitor      — unknown_device_events
  2. Access anomaly detection — access_audit_log analysis
  3. PII protection scanner   — data_protection_findings
"""
from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

# Fixed imports — match existing codebase
from app.models.asset import Asset
from app.models.vulnerability import AssetVulnerability
from app.models.alert import Alert, AlertStatus, AlertSeverity
from app.models.network_monitor import (
    UnknownDeviceEvent,
    AccessAuditLog,
    DataProtectionFinding,
)
from app.services.discovery.scanner_service import get_scanner, ScannerError

logger = logging.getLogger(__name__)


def _fingerprint(title: str) -> str:
    return hashlib.sha256(title.encode()).hexdigest()[:64]


async def _create_alert(
    db: AsyncSession, tenant_id, title: str, message: str, severity: str,
    asset_id=None, asset_name=None, context_data: Optional[dict] = None,
) -> Optional[Alert]:
    try:
        alert = Alert(
            tenant_id=tenant_id,
            rule_id=None,
            title=title,
            message=message,
            severity=severity,
            status=AlertStatus.OPEN.value,
            fingerprint=_fingerprint(f"{tenant_id}:{title}"),
            asset_id=asset_id,
            asset_name=asset_name,
            context_data=context_data,
            triggered_at=datetime.now(timezone.utc).isoformat(),
        )
        db.add(alert)
        await db.flush()
        return alert
    except Exception:
        logger.exception("Failed to create alert '%s'", title)
        return None


# =============================================================================
# 1. WIFI DEVICE MONITOR
# =============================================================================

async def _known_mac_addresses(db: AsyncSession, tenant_id) -> set[str]:
    """Returns MAC addresses already in the Asset inventory for this tenant."""
    try:
        # MACs are stored in custom_attributes by the discovery module
        result = await db.execute(
            select(Asset).where(
                Asset.tenant_id == tenant_id,
                Asset.custom_attributes.is_not(None),
            )
        )
        assets = result.scalars().all()
        macs: set[str] = set()
        for asset in assets:
            if asset.custom_attributes:
                mac = asset.custom_attributes.get("mac_address")
                if mac:
                    macs.add(str(mac).upper())
        return macs
    except Exception:
        logger.exception("Failed to fetch known MAC addresses for tenant %s", tenant_id)
        return set()


async def scan_for_unknown_devices(
    db: AsyncSession, tenant_id, ip_range: str, fast: bool = True
) -> dict:
    """Scans ip_range and flags devices not in the Asset inventory by MAC address."""
    try:
        scanner = get_scanner()
        devices, _duration = scanner.scan(
            ip_range=ip_range,
            ports="21-23,80,443,3389,3306,5432",
            fast=fast,
        )
    except ScannerError as e:
        return {"error": str(e), "unknown_devices_found": 0, "alerts_raised": 0, "devices": []}
    except Exception as e:
        return {"error": str(e), "unknown_devices_found": 0, "alerts_raised": 0, "devices": []}

    known_macs = await _known_mac_addresses(db, tenant_id)
    unknown_devices = []
    alerts_raised = 0

    for device in devices:
        if not device.mac_address:
            continue  # Can't identify without MAC

        mac = device.mac_address.upper()
        if mac in known_macs:
            continue

        try:
            existing = (await db.execute(
                select(UnknownDeviceEvent).where(
                    UnknownDeviceEvent.tenant_id == tenant_id,
                    UnknownDeviceEvent.mac_address == mac,
                    UnknownDeviceEvent.is_approved == False,  # noqa: E712
                )
            )).scalar_one_or_none()

            open_ports_json = [
                {"port": p.port, "protocol": p.protocol, "service": p.service}
                for p in device.open_ports
            ]

            if existing:
                existing.ip_address = device.ip_address
                existing.last_seen = datetime.now(timezone.utc)
                existing.hostname = device.hostname or existing.hostname
                existing.open_ports = open_ports_json
                unknown_devices.append(existing)
                continue

            title = f"Unknown Device Detected: {device.hostname or device.ip_address} ({mac})"
            alert = await _create_alert(
                db, tenant_id, title,
                message=f"MAC {mac} at IP {device.ip_address} is not in the asset inventory. Vendor: {device.vendor or 'unknown'}.",
                severity=AlertSeverity.CRITICAL.value,
                context_data={"mac_address": mac, "ip_address": device.ip_address},
            )
            if alert:
                alerts_raised += 1

            event = UnknownDeviceEvent(
                tenant_id=tenant_id,
                ip_address=device.ip_address,
                mac_address=mac,
                vendor=device.vendor,
                hostname=device.hostname,
                open_ports=open_ports_json,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
                alert_id=alert.id if alert else None,
                is_approved=False,
            )
            db.add(event)
            unknown_devices.append(event)

        except Exception:
            logger.exception("Failed to record unknown device %s", mac)

    try:
        await db.commit()
    except Exception:
        logger.exception("Failed to commit unknown device results for tenant %s", tenant_id)
        await db.rollback()
        return {"error": "commit failed", "unknown_devices_found": 0, "alerts_raised": 0, "devices": []}

    return {
        "unknown_devices_found": len(unknown_devices),
        "alerts_raised": alerts_raised,
        "devices": [
            {"id": str(d.id), "ip_address": d.ip_address, "mac_address": d.mac_address,
             "vendor": d.vendor, "hostname": d.hostname}
            for d in unknown_devices
        ],
    }


async def list_unknown_devices(db: AsyncSession, tenant_id) -> list[dict]:
    try:
        result = await db.execute(
            select(UnknownDeviceEvent)
            .where(UnknownDeviceEvent.tenant_id == tenant_id, UnknownDeviceEvent.is_approved == False)  # noqa: E712
            .order_by(UnknownDeviceEvent.last_seen.desc())
        )
        return [
            {
                "id": str(r.id),
                "ip_address": r.ip_address,
                "mac_address": r.mac_address,
                "vendor": r.vendor,
                "hostname": r.hostname,
                "open_ports": r.open_ports,
                "first_seen": r.first_seen.isoformat(),
                "last_seen": r.last_seen.isoformat(),
                "alert_id": str(r.alert_id) if r.alert_id else None,
            }
            for r in result.scalars().all()
        ]
    except Exception:
        logger.exception("Failed to list unknown devices for tenant %s", tenant_id)
        return []


async def approve_unknown_device(db: AsyncSession, tenant_id, event_id, approved_by) -> Optional[dict]:
    try:
        event = await db.get(UnknownDeviceEvent, event_id)
        if not event or event.tenant_id != tenant_id:
            return None
        event.is_approved = True
        event.approved_by = approved_by
        event.approved_at = datetime.now(timezone.utc)
        await db.commit()
        return {
            "id": str(event.id), "is_approved": True,
            "approved_by": str(approved_by), "approved_at": event.approved_at.isoformat(),
        }
    except Exception:
        logger.exception("Failed to approve unknown device %s", event_id)
        await db.rollback()
        return None


# =============================================================================
# 2. DATA ACCESS ANOMALY DETECTION
# =============================================================================

NON_ELEVATED_ROLES = {"viewer", "asset_owner", "executive_viewer"}
SENSITIVE_PREFIXES = [
    "/api/v1/intelligence", "/api/v1/simulate",
    "/api/v1/network/unknown-devices", "/api/v1/network/pii-findings",
    "/api/v1/assessment",
]
IMPOSSIBLE_TRAVEL_WINDOW = 10   # minutes
BULK_ACCESS_THRESHOLD = 50
BULK_ACCESS_WINDOW = 60         # seconds
LOOKBACK_MINUTES = 60


async def analyze_access_patterns(db: AsyncSession, tenant_id, lookback_minutes: int = LOOKBACK_MINUTES) -> dict:
    since = datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
    all_findings: list[dict] = []
    alerts_raised = 0

    # Rule 1: Impossible travel
    try:
        result = await db.execute(
            select(AccessAuditLog)
            .where(AccessAuditLog.tenant_id == tenant_id,
                   AccessAuditLog.accessed_at >= since,
                   AccessAuditLog.user_id.is_not(None))
            .order_by(AccessAuditLog.user_id, AccessAuditLog.accessed_at)
        )
        rows = result.scalars().all()
        by_user: dict = {}
        for row in rows:
            by_user.setdefault(row.user_id, []).append(row)

        window = timedelta(minutes=IMPOSSIBLE_TRAVEL_WINDOW)
        for user_id, events in by_user.items():
            for i in range(len(events)):
                for j in range(i + 1, len(events)):
                    a, b = events[i], events[j]
                    if b.accessed_at - a.accessed_at > window:
                        break
                    if a.ip_address and b.ip_address and a.ip_address != b.ip_address:
                        all_findings.append({
                            "rule": "impossible_travel", "user_id": str(user_id),
                            "ip_a": a.ip_address, "ip_b": b.ip_address,
                            "time_a": a.accessed_at.isoformat(), "time_b": b.accessed_at.isoformat(),
                        })
                        break
    except Exception:
        logger.exception("Impossible travel detection failed for tenant %s", tenant_id)

    # Rule 2: Bulk data harvesting
    try:
        result = await db.execute(
            select(AccessAuditLog)
            .where(AccessAuditLog.tenant_id == tenant_id,
                   AccessAuditLog.accessed_at >= since,
                   AccessAuditLog.user_id.is_not(None),
                   AccessAuditLog.endpoint.like("%/assets%"))
            .order_by(AccessAuditLog.user_id, AccessAuditLog.accessed_at)
        )
        rows = result.scalars().all()
        by_user2: dict = {}
        for row in rows:
            by_user2.setdefault(row.user_id, []).append(row.accessed_at)

        window2 = timedelta(seconds=BULK_ACCESS_WINDOW)
        for user_id, timestamps in by_user2.items():
            timestamps.sort()
            start = 0
            for end in range(len(timestamps)):
                while timestamps[end] - timestamps[start] > window2:
                    start += 1
                if end - start + 1 > BULK_ACCESS_THRESHOLD:
                    all_findings.append({
                        "rule": "bulk_data_harvesting", "user_id": str(user_id),
                        "count": end - start + 1,
                        "window_start": timestamps[start].isoformat(),
                        "window_end": timestamps[end].isoformat(),
                    })
                    break
    except Exception:
        logger.exception("Bulk access detection failed for tenant %s", tenant_id)

    # Rule 3: Privilege probing
    try:
        result = await db.execute(
            select(AccessAuditLog)
            .where(AccessAuditLog.tenant_id == tenant_id,
                   AccessAuditLog.accessed_at >= since,
                   AccessAuditLog.user_role.in_(NON_ELEVATED_ROLES))
        )
        for row in result.scalars().all():
            if any(row.endpoint.startswith(p) for p in SENSITIVE_PREFIXES):
                all_findings.append({
                    "rule": "privilege_probing",
                    "user_id": str(row.user_id) if row.user_id else None,
                    "user_role": row.user_role, "endpoint": row.endpoint,
                    "status_code": row.status_code,
                    "accessed_at": row.accessed_at.isoformat(),
                })
    except Exception:
        logger.exception("Privilege probing detection failed for tenant %s", tenant_id)

    # Fire alerts
    for finding in all_findings:
        try:
            rule = finding["rule"]
            if rule == "impossible_travel":
                title = f"Impossible Travel: user from {finding['ip_a']} and {finding['ip_b']} within {IMPOSSIBLE_TRAVEL_WINDOW} min"
                msg = f"User {finding['user_id']} accessed from two different IPs within {IMPOSSIBLE_TRAVEL_WINDOW} minutes — possible credential compromise."
                sev = AlertSeverity.CRITICAL.value
            elif rule == "bulk_data_harvesting":
                title = f"Bulk Data Access: {finding['count']} asset requests in {BULK_ACCESS_WINDOW}s"
                msg = f"User {finding['user_id']} accessed {finding['count']} asset records rapidly — possible data harvesting."
                sev = AlertSeverity.CRITICAL.value
            else:
                title = f"Privilege Probing: {finding['user_role']} accessed {finding['endpoint']}"
                msg = f"User with role {finding['user_role']} attempted a restricted endpoint."
                sev = AlertSeverity.HIGH.value

            alert = await _create_alert(db, tenant_id, title, msg, sev, context_data=finding)
            if alert:
                alerts_raised += 1
        except Exception:
            logger.exception("Failed to raise alert for access anomaly")

    try:
        await db.commit()
    except Exception:
        logger.exception("Failed to commit access anomaly alerts")
        await db.rollback()
        alerts_raised = 0

    return {"anomalies_found": len(all_findings), "alerts_raised": alerts_raised, "details": all_findings}


# =============================================================================
# 3. PII PROTECTION SCANNER
# =============================================================================

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?<!\d)(\+?\d{1,3}[-.s]?)?(\(?\d{2,4}\)?[-.s]?\d{3,4}[-.s]?\d{3,4})(?!\d)")
_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_SA_ID_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13}(?!\d)")
_PASSPORT_RE = re.compile(r"\b[A-Za-z][-\s]?\d{8}\b")

_PII_SEVERITY = {
    "credit_card": "critical", "sa_id_number": "critical",
    "passport_number": "high", "email": "medium", "phone_number": "medium",
}


def _luhn_check(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _looks_like_sa_id(digits: str) -> bool:
    if len(digits) != 13 or not digits.isdigit():
        return False
    month, day = int(digits[2:4]), int(digits[4:6])
    if not (1 <= month <= 12 and 1 <= day <= 31):
        return False
    return digits[10] in ("0", "1") and _luhn_check(digits)


def _find_pii(text: str) -> list[tuple[str, str]]:
    if not text or not isinstance(text, str):
        return []
    raw: list[tuple[str, re.Match]] = []
    for m in _EMAIL_RE.finditer(text):
        raw.append(("email", m))
    for m in _PASSPORT_RE.finditer(text):
        raw.append(("passport_number", m))
    for m in _SA_ID_RE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group())
        if _looks_like_sa_id(digits):
            raw.append(("sa_id_number", m))
    for m in _CARD_RE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group())
        if 13 <= len(digits) <= 19 and _luhn_check(digits):
            raw.append(("credit_card", m))
    for m in _PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if 7 <= len(digits) <= 15:
            raw.append(("phone_number", m))

    priority = {"credit_card": 0, "sa_id_number": 0, "passport_number": 1, "email": 1, "phone_number": 2}
    raw.sort(key=lambda x: (x[1].start(), priority[x[0]]))

    kept: list[tuple[str, re.Match]] = []
    for pii_type, m in raw:
        if not any(m.start() < k.end() and k.start() < m.end() for _, k in kept):
            kept.append((pii_type, m))
    return [(pii_type, m.group()) for pii_type, m in kept]


def _sample(value: str) -> str:
    c = value.strip()
    return f"{c[:4]}***" if len(c) > 4 else f"{c}***"


async def _scan_field(db: AsyncSession, tenant_id, source_table: str, record_id, field_name: str, value: str) -> list:
    findings = []
    for pii_type, matched in _find_pii(value):
        try:
            f = DataProtectionFinding(
                tenant_id=tenant_id,
                source_table=source_table,
                source_record_id=record_id,
                source_field=field_name,
                pii_type=pii_type,
                pii_sample=_sample(matched),
                severity=_PII_SEVERITY.get(pii_type, "medium"),
                detected_at=datetime.now(timezone.utc),
                is_resolved=False,
            )
            db.add(f)
            findings.append(f)
        except Exception:
            logger.exception("Failed to record PII finding (%s) in %s.%s", pii_type, source_table, field_name)
    return findings


def _flatten_custom_attrs(attrs: dict) -> str:
    if not attrs:
        return ""
    parts = []
    for k, v in attrs.items():
        if k == "open_ports":
            continue
        if isinstance(v, (str, int, float)):
            parts.append(str(v))
        elif isinstance(v, dict):
            parts.append(_flatten_custom_attrs(v))
        elif isinstance(v, list):
            parts.append(" ".join(str(i) for i in v if isinstance(i, (str, int, float))))
    return " ".join(parts)


async def scan_for_pii(db: AsyncSession, tenant_id) -> dict:
    total = 0
    try:
        assets = (await db.execute(select(Asset).where(Asset.tenant_id == tenant_id))).scalars().all()
        for asset in assets:
            for field in ("notes",):
                v = getattr(asset, field, None)
                if v:
                    total += len(await _scan_field(db, tenant_id, "assets", asset.id, field, v))
            if asset.custom_attributes:
                flat = _flatten_custom_attrs(asset.custom_attributes)
                if flat:
                    total += len(await _scan_field(db, tenant_id, "assets", asset.id, "custom_attributes", flat))
    except Exception:
        logger.exception("PII scan failed for assets, tenant %s", tenant_id)

    try:
        vulns = (await db.execute(select(AssetVulnerability).where(AssetVulnerability.tenant_id == tenant_id))).scalars().all()
        for vuln in vulns:
            for field in ("notes",):
                v = getattr(vuln, field, None)
                if v:
                    total += len(await _scan_field(db, tenant_id, "asset_vulnerabilities", vuln.id, field, v))
    except Exception:
        logger.exception("PII scan failed for vulnerabilities, tenant %s", tenant_id)

    try:
        await db.commit()
    except Exception:
        logger.exception("Failed to commit PII findings")
        await db.rollback()
        return {"findings_created": 0, "error": "commit failed"}

    return {"findings_created": total}


async def list_pii_findings(db: AsyncSession, tenant_id) -> list[dict]:
    try:
        result = await db.execute(
            select(DataProtectionFinding)
            .where(DataProtectionFinding.tenant_id == tenant_id,
                   DataProtectionFinding.is_resolved == False)  # noqa: E712
            .order_by(DataProtectionFinding.detected_at.desc())
        )
        return [
            {"id": str(r.id), "source_table": r.source_table,
             "source_record_id": str(r.source_record_id), "source_field": r.source_field,
             "pii_type": r.pii_type, "pii_sample": r.pii_sample,
             "severity": r.severity, "detected_at": r.detected_at.isoformat()}
            for r in result.scalars().all()
        ]
    except Exception:
        logger.exception("Failed to list PII findings for tenant %s", tenant_id)
        return []


async def resolve_pii_finding(db: AsyncSession, tenant_id, finding_id) -> Optional[dict]:
    try:
        finding = await db.get(DataProtectionFinding, finding_id)
        if not finding or finding.tenant_id != tenant_id:
            return None
        finding.is_resolved = True
        finding.resolved_at = datetime.now(timezone.utc)
        await db.commit()
        return {"id": str(finding.id), "is_resolved": True, "resolved_at": finding.resolved_at.isoformat()}
    except Exception:
        logger.exception("Failed to resolve PII finding %s", finding_id)
        await db.rollback()
        return None
