from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CVEOut(BaseModel):
    id: uuid.UUID
    cve_id: str
    description: Optional[str] = None
    cvss_v3_score: Optional[float] = None
    cvss_v3_base_severity: Optional[str] = None
    epss_score: Optional[float] = None
    is_in_kev: bool
    exploit_maturity: Optional[str] = None
    has_public_exploit: bool
    published_date: Optional[str] = None

    model_config = {"from_attributes": True}


class AssetVulnerabilityCreate(BaseModel):
    asset_id: uuid.UUID
    cve_id: Optional[str] = None
    priority: str = "medium"
    affected_component: Optional[str] = None
    affected_version: Optional[str] = None
    fix_version: Optional[str] = None
    detection_source: Optional[str] = None
    notes: Optional[str] = None


class AssetVulnerabilityUpdate(BaseModel):
    status: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[uuid.UUID] = None
    notes: Optional[str] = None
    false_positive_reason: Optional[str] = None
    accepted_risk_reason: Optional[str] = None


class AssetVulnerabilityOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    asset_id: uuid.UUID
    cve_id: Optional[str] = None
    priority: str
    status: str
    affected_component: Optional[str] = None
    affected_version: Optional[str] = None
    fix_version: Optional[str] = None
    risk_score: Optional[float] = None
    sla_status: str
    sla_deadline: Optional[str] = None
    first_detected_at: Optional[str] = None
    remediated_at: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime
    # Joined CVE data
    cvss_v3_score: Optional[float] = None
    epss_score: Optional[float] = None
    is_in_kev: Optional[bool] = None
    exploit_maturity: Optional[str] = None

    model_config = {"from_attributes": True}


class VulnerabilitySummary(BaseModel):
    open_critical: int
    open_high: int
    open_medium: int
    open_low: int
    kev_count: int
    exploit_available: int
    sla_breached_critical: int
    sla_breached_high: int
    delta_7d_critical: int
    total_open: int


class VulnerabilityListResponse(BaseModel):
    vulnerabilities: List[AssetVulnerabilityOut]
    total: int
    page: int
    per_page: int
