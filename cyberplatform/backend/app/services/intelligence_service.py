"""
app/services/intelligence_service.py
Four responsibilities:
  generate_briefing()      -- Groq-powered (or template fallback) briefing
  compute_predictions()    -- pattern-based "likely next vulnerable asset"
  get_trends()             -- 7-day deltas on posture metrics
  run_anomaly_detection()  -- fires Alerts on significant changes
"""
from __future__ import annotations

import hashlib
import logging
import os
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

# All imports fixed to match existing codebase paths
from app.models.asset import Asset
from app.models.vulnerability import AssetVulnerability
from app.models.attack_simulation_result import AttackSimulationResult
from app.models.alert import Alert, AlertStatus, AlertSeverity
from app.models.risk import AssetRiskScore, OrgRiskScore
from app.models.intelligence import AssetRiskPrediction, SecurityPostureSnapshot
from app.db.redis_client import get_redis

logger = logging.getLogger(__name__)

GROQ_TIMEOUT_SECONDS = 10
GROQ_MODEL = "llama-3.3-70b-versatile"
BRIEFING_CACHE_TTL_SECONDS = 4 * 60 * 60  # 4 hours

AUDIENCE_WORD_TARGETS = {
    "executive": 100,
    "analyst": 300,
    "owner": 150,
}

OPEN_VULN_STATUSES = [
    "discovered", "triaged", "assigned", "in_remediation", "pending_verification"
]


# =============================================================================
# Shared data helpers (all tenant-scoped, all exception-safe)
# =============================================================================

async def _get_org_risk_score(db: AsyncSession, tenant_id) -> Optional[float]:
    try:
        # OrgRiskScore has one row per tenant, updated in place
        stmt = select(OrgRiskScore).where(OrgRiskScore.tenant_id == tenant_id)
        result = await db.execute(stmt)
        row = result.scalar_one_or_none()
        return float(row.risk_score) if row else None
    except Exception:
        logger.exception("Failed to fetch org risk score for tenant %s", tenant_id)
        return None


async def _get_top_risky_assets(db: AsyncSession, tenant_id, limit: int = 3) -> list[dict]:
    try:
        stmt = (
            select(AssetRiskScore, Asset)
            .join(Asset, Asset.id == AssetRiskScore.asset_id)
            .where(AssetRiskScore.tenant_id == tenant_id)
            .order_by(AssetRiskScore.risk_score.desc())
            .limit(limit)
        )
        result = await db.execute(stmt)
        return [
            {
                "asset_id": str(asset.id),
                "asset_name": asset.name or str(asset.id),
                "score": float(risk.risk_score),
                "risk_band": risk.risk_band,
            }
            for risk, asset in result.all()
        ]
    except Exception:
        logger.exception("Failed to fetch top risky assets for tenant %s", tenant_id)
        return []


async def _get_critical_open_vulns(db: AsyncSession, tenant_id, limit: int = 10) -> list[dict]:
    try:
        stmt = (
            select(AssetVulnerability, Asset)
            .join(Asset, Asset.id == AssetVulnerability.asset_id)
            .where(
                AssetVulnerability.tenant_id == tenant_id,
                AssetVulnerability.priority == "critical",
                AssetVulnerability.status.in_(OPEN_VULN_STATUSES),
            )
            .limit(limit)
        )
        result = await db.execute(stmt)
        return [
            {
                "cve_id": vuln.cve_id,
                "asset_name": asset.name or str(asset.id),
                "affected_component": vuln.affected_component,
                "sla_deadline": vuln.sla_deadline,
                "sla_status": vuln.sla_status,
            }
            for vuln, asset in result.all()
        ]
    except Exception:
        logger.exception("Failed to fetch critical vulns for tenant %s", tenant_id)
        return []


async def _get_confirmed_exposures(db: AsyncSession, tenant_id, limit: int = 10) -> list[dict]:
    try:
        stmt = (
            select(AttackSimulationResult, Asset)
            .join(Asset, Asset.id == AttackSimulationResult.asset_id)
            .where(
                AttackSimulationResult.tenant_id == tenant_id,
                AttackSimulationResult.was_successful.is_(True),
            )
            .order_by(AttackSimulationResult.simulated_at.desc())
            .limit(limit)
        )
        result = await db.execute(stmt)
        return [
            {
                "asset_name": asset.name or str(asset.id),
                "finding_title": sim.finding_title,
                "severity": sim.severity,
            }
            for sim, asset in result.all()
        ]
    except Exception:
        logger.exception("Failed to fetch confirmed exposures for tenant %s", tenant_id)
        return []


# =============================================================================
# 1. THREAT BRIEFING
# =============================================================================

def _build_briefing_prompt(audience: str, data: dict) -> str:
    word_target = AUDIENCE_WORD_TARGETS[audience]
    style = {
        "executive": "Write for a non-technical executive. Business language only, no jargon. Focus on business risk.",
        "analyst": "Write for a security analyst. Use precise technical detail: CVE IDs, ports, affected components.",
        "owner": "Write for the owner of the assets. Plain language, focus on what they personally need to do.",
    }[audience]
    return f"""You are a security operations assistant writing a daily security briefing.

{style}
Target length: approximately {word_target} words.

Data:
- Org risk score: {data['org_risk_score']}
- Top risky assets: {data['top_assets']}
- Critical open vulnerabilities: {data['critical_vulns']}
- Confirmed real exposures from attack simulation: {data['confirmed_exposures']}

Write the briefing now. Include: risk posture summary, top risky assets, critical vulns needing action,
confirmed exposures, and end with exactly one recommended action for today.
Output only the briefing text, no headers or preamble."""


def _template_briefing(audience: str, data: dict) -> str:
    score = data["org_risk_score"]
    top = data["top_assets"]
    crit = data["critical_vulns"]
    exp = data["confirmed_exposures"]

    top_str = "; ".join(f"{a['asset_name']} (risk {a['score']:.0f})" for a in top) or "none scored yet"
    crit_str = "; ".join(f"{v['cve_id'] or v['affected_component']} on {v['asset_name']}" for v in crit) or "none"
    exp_str = "; ".join(f"{e['finding_title']} on {e['asset_name']}" for e in exp) or "none confirmed"

    if audience == "executive":
        return (
            f"Organization risk score: {score if score is not None else 'not yet calculated'}. "
            f"Highest-risk systems: {top_str}. "
            f"{len(crit)} critical issues need attention and {len(exp)} confirmed real security gaps were found. "
            f"Recommended action today: prioritize remediation of confirmed exposures first — "
            f"these represent verified, exploitable risk."
        )
    elif audience == "analyst":
        return (
            f"Org risk score: {score}.\n"
            f"Top risky assets: {top_str}.\n"
            f"Critical open vulns: {crit_str}.\n"
            f"Confirmed exposures (was_successful=True): {exp_str}.\n"
            f"Recommended action: triage confirmed exposures first, then critical vulns by SLA deadline."
        )
    else:
        return (
            f"Today's summary. Overall risk score: {score}. "
            f"Your highest-priority assets: {top_str}. "
            f"Critical issues needing fixing: {crit_str}. "
            f"Confirmed real exposures found: {exp_str}. "
            f"Recommended action: address confirmed exposures listed above first."
        )


async def _call_groq(prompt: str) -> Optional[str]:
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        logger.info("GROQ_API_KEY not set; using template briefing.")
        return None
    try:
        from groq import Groq
        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500,
            timeout=GROQ_TIMEOUT_SECONDS,
        )
        return response.choices[0].message.content
    except Exception:
        logger.exception("Groq API call failed; using template briefing.")
        return None


async def generate_briefing(db: AsyncSession, tenant_id, audience: str) -> dict:
    if audience not in AUDIENCE_WORD_TARGETS:
        raise ValueError(f"Invalid audience '{audience}'")

    cache_key = f"intelligence:briefing:{tenant_id}:{audience}"
    redis = None
    try:
        redis = await get_redis()
        cached = await redis.get(cache_key)
        if cached:
            import json
            return json.loads(cached)
    except Exception:
        logger.exception("Redis cache read failed for %s", cache_key)

    data = {
        "org_risk_score": await _get_org_risk_score(db, tenant_id),
        "top_assets": await _get_top_risky_assets(db, tenant_id),
        "critical_vulns": await _get_critical_open_vulns(db, tenant_id),
        "confirmed_exposures": await _get_confirmed_exposures(db, tenant_id),
    }

    ai_text = await _call_groq(_build_briefing_prompt(audience, data))
    briefing_text = ai_text or _template_briefing(audience, data)

    result = {
        "briefing": briefing_text,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "audience": audience,
    }

    if redis is not None:
        try:
            import json
            await redis.set(cache_key, json.dumps(result), ex=BRIEFING_CACHE_TTL_SECONDS)
        except Exception:
            logger.exception("Redis cache write failed for %s", cache_key)

    return result


# =============================================================================
# 2. PATTERN LEARNING
# =============================================================================

async def compute_predictions(db: AsyncSession, tenant_id) -> list[dict]:
    predictions: list[dict] = []
    try:
        unscanned = (await db.execute(
            select(Asset).where(Asset.tenant_id == tenant_id, Asset.last_scan_date.is_(None), Asset.is_deleted == False)  # noqa: E712
        )).scalars().all()
    except Exception:
        logger.exception("Failed to fetch unscanned assets for tenant %s", tenant_id)
        return predictions

    for asset in unscanned:
        try:
            similar = (await db.execute(
                select(Asset).where(
                    Asset.tenant_id == tenant_id,
                    Asset.asset_type == asset.asset_type,
                    Asset.environment == asset.environment,
                    Asset.last_scan_date.is_not(None),
                    Asset.id != asset.id,
                )
            )).scalars().all()

            if not similar:
                continue

            similar_ids = [a.id for a in similar]
            total_critical = (await db.execute(
                select(func.count(AssetVulnerability.id)).where(
                    AssetVulnerability.tenant_id == tenant_id,
                    AssetVulnerability.asset_id.in_(similar_ids),
                    AssetVulnerability.priority == "critical",
                )
            )).scalar_one() or 0

            avg_critical = total_critical / len(similar)
            if avg_critical < 2:
                continue

            confidence = min(len(similar) / 10, 0.95)
            reason = (
                f"{len(similar)} other {asset.asset_type or 'similar'} asset(s) in "
                f"{asset.environment or 'same'} environment averaged "
                f"{avg_critical:.1f} critical findings. This asset has not been scanned yet."
            )

            db.add(AssetRiskPrediction(
                tenant_id=tenant_id,
                asset_id=asset.id,
                predicted_severity="critical",
                confidence_score=round(confidence, 3),
                prediction_reason=reason,
                based_on_asset_count=len(similar),
            ))
            predictions.append({
                "asset_id": str(asset.id),
                "asset_name": asset.name or str(asset.id),
                "predicted_severity": "critical",
                "confidence_score": round(confidence, 3),
                "prediction_reason": reason,
                "based_on_asset_count": len(similar),
            })
        except Exception:
            logger.exception("Prediction failed for asset %s", asset.id)

    try:
        await db.commit()
    except Exception:
        logger.exception("Failed to commit predictions for tenant %s", tenant_id)
        await db.rollback()

    predictions.sort(key=lambda p: -p["confidence_score"])
    return predictions


async def get_predictions(db: AsyncSession, tenant_id) -> list[dict]:
    try:
        result = await db.execute(
            select(AssetRiskPrediction, Asset)
            .join(Asset, Asset.id == AssetRiskPrediction.asset_id)
            .where(AssetRiskPrediction.tenant_id == tenant_id)
            .order_by(AssetRiskPrediction.confidence_score.desc())
        )
        return [
            {
                "asset_id": str(pred.asset_id),
                "asset_name": asset.name or str(asset.id),
                "predicted_severity": pred.predicted_severity,
                "confidence_score": float(pred.confidence_score),
                "prediction_reason": pred.prediction_reason,
                "based_on_asset_count": pred.based_on_asset_count,
                "created_at": pred.created_at.isoformat(),
            }
            for pred, asset in result.all()
        ]
    except Exception:
        logger.exception("Failed to fetch predictions for tenant %s", tenant_id)
        return []


# =============================================================================
# 3. TREND ANALYSIS
# =============================================================================

_LOWER_IS_BETTER = {
    "org_risk_score", "open_critical_vulns", "open_high_vulns",
    "assets_with_exposures", "total_simulation_findings",
}


def _direction(metric: str, delta: float) -> str:
    if delta == 0:
        return "stable"
    return "improving" if ((delta < 0) if metric in _LOWER_IS_BETTER else (delta > 0)) else "degrading"


async def _current_metrics(db: AsyncSession, tenant_id) -> dict:
    org_risk = await _get_org_risk_score(db, tenant_id) or 0.0

    try:
        open_critical = (await db.execute(
            select(func.count(AssetVulnerability.id)).where(
                AssetVulnerability.tenant_id == tenant_id,
                AssetVulnerability.priority == "critical",
                AssetVulnerability.status.in_(OPEN_VULN_STATUSES),
            )
        )).scalar_one() or 0
        open_high = (await db.execute(
            select(func.count(AssetVulnerability.id)).where(
                AssetVulnerability.tenant_id == tenant_id,
                AssetVulnerability.priority == "high",
                AssetVulnerability.status.in_(OPEN_VULN_STATUSES),
            )
        )).scalar_one() or 0
    except Exception:
        open_critical = open_high = 0

    try:
        total_crit = (await db.execute(
            select(func.count(AssetVulnerability.id)).where(
                AssetVulnerability.tenant_id == tenant_id, AssetVulnerability.priority == "critical"
            )
        )).scalar_one() or 0
        closed_crit = (await db.execute(
            select(func.count(AssetVulnerability.id)).where(
                AssetVulnerability.tenant_id == tenant_id,
                AssetVulnerability.priority == "critical",
                AssetVulnerability.status == "closed",
            )
        )).scalar_one() or 0
        sla_rate = (closed_crit / total_crit * 100) if total_crit else 100.0
    except Exception:
        sla_rate = 0.0

    try:
        assets_scanned = (await db.execute(
            select(func.count(Asset.id)).where(
                Asset.tenant_id == tenant_id, Asset.last_scan_date.is_not(None)
            )
        )).scalar_one() or 0
    except Exception:
        assets_scanned = 0

    try:
        assets_exposed = (await db.execute(
            select(func.count(func.distinct(AttackSimulationResult.asset_id))).where(
                AttackSimulationResult.tenant_id == tenant_id,
                AttackSimulationResult.was_successful.is_(True),
            )
        )).scalar_one() or 0
        total_sim = (await db.execute(
            select(func.count(AttackSimulationResult.id)).where(
                AttackSimulationResult.tenant_id == tenant_id
            )
        )).scalar_one() or 0
    except Exception:
        assets_exposed = total_sim = 0

    return {
        "org_risk_score": float(org_risk),
        "open_critical_vulns": int(open_critical),
        "open_high_vulns": int(open_high),
        "sla_compliance_rate": round(float(sla_rate), 2),
        "assets_scanned": int(assets_scanned),
        "assets_with_exposures": int(assets_exposed),
        "total_simulation_findings": int(total_sim),
    }


async def get_trends(db: AsyncSession, tenant_id) -> dict:
    current = await _current_metrics(db, tenant_id)
    baseline = {k: None for k in current}

    try:
        seven_days_ago = date.today() - timedelta(days=7)
        result = await db.execute(
            select(SecurityPostureSnapshot)
            .where(SecurityPostureSnapshot.tenant_id == tenant_id,
                   SecurityPostureSnapshot.snapshot_date <= seven_days_ago)
            .order_by(SecurityPostureSnapshot.snapshot_date.desc())
            .limit(1)
        )
        snap = result.scalar_one_or_none()
        if snap:
            baseline = {
                "org_risk_score": float(snap.org_risk_score),
                "open_critical_vulns": snap.open_critical_vulns,
                "open_high_vulns": snap.open_high_vulns,
                "sla_compliance_rate": float(snap.sla_compliance_rate),
                "assets_scanned": snap.assets_scanned,
                "assets_with_exposures": snap.assets_with_exposures,
                "total_simulation_findings": snap.total_simulation_findings,
            }
    except Exception:
        logger.exception("Failed to fetch 7d snapshot for tenant %s", tenant_id)

    return {
        metric: {
            "current_value": current[metric],
            "value_7d_ago": baseline[metric],
            "delta": None if baseline[metric] is None else round(current[metric] - baseline[metric], 2),
            "direction": "unknown" if baseline[metric] is None else _direction(metric, current[metric] - baseline[metric]),
        }
        for metric in current
    }


async def take_snapshot(db: AsyncSession, tenant_id) -> dict:
    metrics = await _current_metrics(db, tenant_id)
    try:
        snap = SecurityPostureSnapshot(
            tenant_id=tenant_id,
            snapshot_date=date.today(),
            **metrics,
        )
        db.add(snap)
        await db.commit()
        return {"status": "saved", "snapshot_date": snap.snapshot_date.isoformat(), **metrics}
    except Exception:
        logger.exception("Failed to save snapshot for tenant %s", tenant_id)
        await db.rollback()
        return {"status": "failed", "snapshot_date": None, **metrics}


# =============================================================================
# 4. ANOMALY DETECTION
# =============================================================================

def _fp(title: str) -> str:
    return hashlib.sha256(title.encode()).hexdigest()[:64]


async def _create_alert(db, tenant_id, title, message, severity, asset_id=None, asset_name=None, context_data=None):
    try:
        alert = Alert(
            tenant_id=tenant_id,
            rule_id=None,
            title=title,
            message=message,
            severity=severity,
            status=AlertStatus.OPEN.value,
            fingerprint=_fp(f"{tenant_id}:{title}"),
            asset_id=asset_id,
            asset_name=asset_name,
            context_data=context_data,
            triggered_at=datetime.now(timezone.utc).isoformat(),
        )
        db.add(alert)
        return alert
    except Exception:
        logger.exception("Failed to create alert '%s'", title)
        return None


async def run_anomaly_detection(db: AsyncSession, tenant_id) -> dict:
    anomalies: list[dict] = []
    alerts_raised = 0
    current = await _current_metrics(db, tenant_id)

    try:
        result = await db.execute(
            select(SecurityPostureSnapshot)
            .where(SecurityPostureSnapshot.tenant_id == tenant_id)
            .order_by(SecurityPostureSnapshot.snapshot_date.desc())
            .limit(1)
        )
        previous = result.scalar_one_or_none()
    except Exception:
        previous = None

    # Rule 1: Risk spike
    if previous is not None:
        try:
            delta = current["org_risk_score"] - float(previous.org_risk_score)
            if delta > 10:
                title = f"Risk Score Spike: Organization risk increased by {delta:.1f} points"
                anomalies.append({"rule": "org_risk_spike", "delta": delta})
                alert = await _create_alert(db, tenant_id, title,
                    f"Risk score rose from {previous.org_risk_score} to {current['org_risk_score']}.",
                    AlertSeverity.HIGH.value,
                    context_data={"previous": float(previous.org_risk_score), "current": current["org_risk_score"]})
                if alert:
                    alerts_raised += 1
        except Exception:
            logger.exception("Rule org_risk_spike failed")

    # Rule 2: New confirmed exposures since last snapshot
    try:
        since = previous.created_at if previous else datetime.min.replace(tzinfo=timezone.utc)
        result = await db.execute(
            select(AttackSimulationResult, Asset)
            .join(Asset, Asset.id == AttackSimulationResult.asset_id)
            .where(
                AttackSimulationResult.tenant_id == tenant_id,
                AttackSimulationResult.was_successful.is_(True),
                AttackSimulationResult.simulated_at > since,
            )
        )
        for sim, asset in result.all():
            asset_name = asset.name or str(asset.id)
            title = f"Confirmed Exposure Detected: {asset_name} has a verified security gap"
            anomalies.append({"rule": "new_confirmed_exposure", "asset_id": str(asset.id)})
            alert = await _create_alert(db, tenant_id, title, sim.finding_detail,
                AlertSeverity.CRITICAL.value, asset_id=asset.id, asset_name=asset_name,
                context_data={"finding_title": sim.finding_title})
            if alert:
                alerts_raised += 1
    except Exception:
        logger.exception("Rule new_confirmed_exposure failed")

    # Rule 3: SLA compliance below 60%
    try:
        if current["sla_compliance_rate"] < 60:
            title = f"SLA Breach Warning: Only {current['sla_compliance_rate']:.1f}% of critical vulns remediated on time"
            anomalies.append({"rule": "sla_breach", "rate": current["sla_compliance_rate"]})
            alert = await _create_alert(db, tenant_id, title,
                f"SLA compliance is {current['sla_compliance_rate']:.1f}%, below 60% threshold.",
                AlertSeverity.HIGH.value, context_data={"rate": current["sla_compliance_rate"]})
            if alert:
                alerts_raised += 1
    except Exception:
        logger.exception("Rule sla_breach failed")

    # Rule 4: Critical vuln spike
    if previous is not None:
        try:
            new_crit = current["open_critical_vulns"] - previous.open_critical_vulns
            if new_crit > 5:
                title = f"Critical Vulnerability Spike: {new_crit} new critical findings detected"
                anomalies.append({"rule": "critical_vuln_spike", "count": new_crit})
                alert = await _create_alert(db, tenant_id, title,
                    f"Open critical vulns increased from {previous.open_critical_vulns} to {current['open_critical_vulns']}.",
                    AlertSeverity.HIGH.value,
                    context_data={"previous": previous.open_critical_vulns, "current": current["open_critical_vulns"]})
                if alert:
                    alerts_raised += 1
        except Exception:
            logger.exception("Rule critical_vuln_spike failed")

    try:
        await db.commit()
    except Exception:
        logger.exception("Failed to commit anomaly alerts for tenant %s", tenant_id)
        await db.rollback()
        alerts_raised = 0

    return {"anomalies_found": len(anomalies), "alerts_raised": alerts_raised, "details": anomalies}
