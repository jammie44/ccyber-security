from __future__ import annotations

import uuid
from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import get_db
from app.middleware.auth import CurrentUser, require_role
from app.models.user import UserRole
from app.schemas.alert import (
    AlertAcknowledgeRequest,
    AlertBulkAcknowledgeRequest,
    AlertListResponse,
    AlertOut,
    AlertResolveRequest,
    AlertRuleCreate,
    AlertRuleOut,
    AlertRuleToggle,
)
from app.services.alert_service import AlertService

router = APIRouter()


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    status: Optional[List[str]] = Query(default=None),
    severity: Optional[List[str]] = Query(default=None),
    page: int = 1,
    per_page: int = 50,
) -> AlertListResponse:
    service = AlertService(db)
    alerts, total, summary = await service.list_alerts(
        user.tenant_id, status_filter=status, severity_filter=severity, page=page, per_page=per_page
    )
    return AlertListResponse(
        alerts=[AlertOut.model_validate(a) for a in alerts],
        total=total,
        summary=summary,
    )


@router.post("/{alert_id}/acknowledge", response_model=AlertOut)
async def acknowledge_alert(
    alert_id: uuid.UUID,
    payload: AlertAcknowledgeRequest,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AlertOut:
    service = AlertService(db)
    alert = await service.acknowledge_alert(user.tenant_id, alert_id, user.id)
    return AlertOut.model_validate(alert)


@router.post("/{alert_id}/resolve", response_model=AlertOut)
async def resolve_alert(
    alert_id: uuid.UUID,
    payload: AlertResolveRequest,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AlertOut:
    service = AlertService(db)
    alert = await service.resolve_alert(user.tenant_id, alert_id, payload.reason)
    return AlertOut.model_validate(alert)


@router.post("/bulk/acknowledge")
async def bulk_acknowledge(
    payload: AlertBulkAcknowledgeRequest,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    service = AlertService(db)
    count = await service.bulk_acknowledge(user.tenant_id, payload.alert_ids, user.id)
    return {"acknowledged": count}


@router.get("/rules", response_model=list[AlertRuleOut])
async def list_rules(user: CurrentUser, db: Annotated[AsyncSession, Depends(get_db)]):
    service = AlertService(db)
    rules = await service.list_rules(user.tenant_id)
    return [AlertRuleOut.model_validate(r) for r in rules]


@router.post("/rules", response_model=AlertRuleOut, status_code=201)
async def create_rule(
    payload: AlertRuleCreate,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, require_role(UserRole.SECURITY_MANAGER)] = None,
):
    service = AlertService(db)
    rule = await service.create_rule(user.tenant_id, payload)
    return AlertRuleOut.model_validate(rule)


@router.post("/rules/{rule_id}/toggle", response_model=AlertRuleOut)
async def toggle_rule(
    rule_id: uuid.UUID,
    payload: AlertRuleToggle,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, require_role(UserRole.SECURITY_MANAGER)] = None,
):
    service = AlertService(db)
    rule = await service.toggle_rule(user.tenant_id, rule_id, payload.is_active)
    return AlertRuleOut.model_validate(rule)
