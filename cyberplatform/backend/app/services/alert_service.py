from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import HTTPException, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.redis_client import get_redis
from app.models.alert import Alert, AlertRule, AlertStatus
from app.schemas.alert import AlertRuleCreate


class AlertService:
    def __init__(self, db: AsyncSession):
        self.db = db

    def _compute_fingerprint(self, rule: AlertRule, event_data: dict) -> str:
        h = hashlib.sha256()
        for field in (rule.dedup_key_fields or []):
            h.update(f"{field}={event_data.get(field, '')};".encode())
        h.update(f"rule={rule.id};".encode())
        return h.hexdigest()[:16]

    async def fire_alert(
        self,
        tenant_id: uuid.UUID,
        rule: AlertRule,
        title: str,
        message: str,
        severity: str,
        asset_id: Optional[uuid.UUID] = None,
        asset_name: Optional[str] = None,
        event_data: Optional[dict] = None,
    ) -> Optional[Alert]:
        event_data = event_data or {}
        fingerprint = self._compute_fingerprint(rule, event_data)

        redis = await get_redis()
        dedup_key = f"alert:dedup:{tenant_id}:{fingerprint}"
        is_new = await redis.set(dedup_key, "1", ex=rule.dedup_window_minutes * 60, nx=True)

        if not is_new:
            # Increment suppressed_count on the most recent matching alert
            result = await self.db.execute(
                select(Alert)
                .where(Alert.tenant_id == tenant_id, Alert.fingerprint == fingerprint)
                .order_by(Alert.created_at.desc())
                .limit(1)
            )
            existing = result.scalar_one_or_none()
            if existing:
                existing.suppressed_count += 1
                await self.db.commit()
            return None

        now = datetime.now(timezone.utc).isoformat()
        alert = Alert(
            tenant_id=tenant_id,
            rule_id=rule.id,
            title=title,
            message=message,
            severity=severity,
            status=AlertStatus.OPEN.value,
            fingerprint=fingerprint,
            asset_id=asset_id,
            asset_name=asset_name,
            context_data=event_data,
            triggered_at=now,
        )
        self.db.add(alert)
        await self.db.commit()
        await self.db.refresh(alert)
        return alert

    async def list_alerts(
        self,
        tenant_id: uuid.UUID,
        *,
        status_filter: Optional[list[str]] = None,
        severity_filter: Optional[list[str]] = None,
        page: int = 1,
        per_page: int = 50,
    ) -> tuple[list[Alert], int, dict]:
        conditions = [Alert.tenant_id == tenant_id]
        if status_filter:
            conditions.append(Alert.status.in_(status_filter))
        if severity_filter:
            conditions.append(Alert.severity.in_(severity_filter))

        stmt = select(Alert).where(and_(*conditions)).order_by(Alert.created_at.desc())
        stmt = stmt.offset((page - 1) * per_page).limit(per_page)
        result = await self.db.execute(stmt)
        alerts = result.scalars().all()

        count_stmt = select(func.count()).select_from(Alert).where(and_(*conditions))
        total = (await self.db.execute(count_stmt)).scalar_one()

        summary = {}
        for sev in ("critical", "high", "medium", "low"):
            sev_count = (await self.db.execute(
                select(func.count()).select_from(Alert).where(
                    Alert.tenant_id == tenant_id, Alert.status == "open", Alert.severity == sev
                )
            )).scalar_one()
            summary[f"open_{sev}"] = sev_count

        return alerts, total, summary

    async def acknowledge_alert(self, tenant_id: uuid.UUID, alert_id: uuid.UUID, user_id: uuid.UUID) -> Alert:
        alert = await self._get_alert(tenant_id, alert_id)
        alert.status = AlertStatus.ACKNOWLEDGED.value
        alert.acknowledged_at = datetime.now(timezone.utc).isoformat()
        alert.acknowledged_by = user_id
        await self.db.commit()
        await self.db.refresh(alert)
        return alert

    async def resolve_alert(self, tenant_id: uuid.UUID, alert_id: uuid.UUID, reason: str) -> Alert:
        alert = await self._get_alert(tenant_id, alert_id)
        alert.status = AlertStatus.RESOLVED.value
        alert.resolved_at = datetime.now(timezone.utc).isoformat()
        alert.resolved_reason = reason
        await self.db.commit()
        await self.db.refresh(alert)
        return alert

    async def bulk_acknowledge(self, tenant_id: uuid.UUID, alert_ids: list[uuid.UUID], user_id: uuid.UUID) -> int:
        result = await self.db.execute(
            select(Alert).where(Alert.tenant_id == tenant_id, Alert.id.in_(alert_ids))
        )
        alerts = result.scalars().all()
        now = datetime.now(timezone.utc).isoformat()
        for a in alerts:
            a.status = AlertStatus.ACKNOWLEDGED.value
            a.acknowledged_at = now
            a.acknowledged_by = user_id
        await self.db.commit()
        return len(alerts)

    async def _get_alert(self, tenant_id: uuid.UUID, alert_id: uuid.UUID) -> Alert:
        result = await self.db.execute(
            select(Alert).where(Alert.id == alert_id, Alert.tenant_id == tenant_id)
        )
        alert = result.scalar_one_or_none()
        if not alert:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
        return alert

    # ── Alert Rules ───────────────────────────────────────────────────────
    async def list_rules(self, tenant_id: uuid.UUID) -> list[AlertRule]:
        result = await self.db.execute(select(AlertRule).where(AlertRule.tenant_id == tenant_id))
        return result.scalars().all()

    async def create_rule(self, tenant_id: uuid.UUID, payload: AlertRuleCreate) -> AlertRule:
        rule = AlertRule(
            tenant_id=tenant_id,
            name=payload.name,
            trigger_type=payload.trigger_type,
            event_types=payload.event_types,
            condition=payload.condition,
            environments=payload.environments,
            severity=payload.severity,
            title_template=payload.title_template,
            message_template=payload.message_template,
            notification_channels=payload.notification_channels,
            notification_targets=payload.notification_targets,
            dedup_key_fields=["asset_id", "event_type"],
            dedup_window_minutes=payload.dedup_window_minutes,
            auto_resolve=payload.auto_resolve,
            is_builtin=False,
        )
        self.db.add(rule)
        await self.db.commit()
        await self.db.refresh(rule)
        return rule

    async def toggle_rule(self, tenant_id: uuid.UUID, rule_id: uuid.UUID, is_active: bool) -> AlertRule:
        result = await self.db.execute(
            select(AlertRule).where(AlertRule.id == rule_id, AlertRule.tenant_id == tenant_id)
        )
        rule = result.scalar_one_or_none()
        if not rule:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert rule not found")
        rule.is_active = is_active
        await self.db.commit()
        await self.db.refresh(rule)
        return rule
