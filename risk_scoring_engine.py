from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class AlertOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    title: str
    message: Optional[str] = None
    severity: str
    status: str
    fingerprint: str
    asset_id: Optional[uuid.UUID] = None
    asset_name: Optional[str] = None
    context_data: Optional[Any] = None
    suppressed_count: int
    triggered_at: Optional[str] = None
    acknowledged_at: Optional[str] = None
    resolved_at: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertListResponse(BaseModel):
    alerts: List[AlertOut]
    total: int
    summary: Dict[str, int]


class AlertAcknowledgeRequest(BaseModel):
    notes: Optional[str] = None


class AlertResolveRequest(BaseModel):
    reason: str


class AlertBulkAcknowledgeRequest(BaseModel):
    alert_ids: List[uuid.UUID]
    notes: Optional[str] = None


class AlertRuleOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    trigger_type: str
    event_types: Optional[Any] = None
    severity: str
    title_template: str
    is_active: bool
    is_builtin: bool
    notification_channels: Optional[Any] = None
    dedup_window_minutes: int
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertRuleCreate(BaseModel):
    name: str
    trigger_type: str = "event_based"
    event_types: Optional[List[str]] = None
    condition: Optional[Dict[str, Any]] = None
    environments: Optional[List[str]] = None
    severity: str = "medium"
    title_template: str
    message_template: Optional[str] = None
    notification_channels: Optional[List[str]] = None
    notification_targets: Optional[Dict[str, Any]] = None
    dedup_window_minutes: int = 60
    auto_resolve: bool = False


class AlertRuleToggle(BaseModel):
    is_active: bool
