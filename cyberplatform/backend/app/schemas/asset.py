from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AssetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=500)
    asset_type: str = "other"
    environment: str = "production"
    criticality_score: float = Field(default=5.0, ge=0, le=10)
    business_impact_score: float = Field(default=5.0, ge=0, le=10)
    data_classification: str = "internal"
    exposure_level: str = "internal"
    is_internet_facing: bool = False
    is_in_compliance_scope: bool = False
    ip_addresses: Optional[List[str]] = None
    hostnames: Optional[List[str]] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    cloud_provider: Optional[str] = None
    cloud_region: Optional[str] = None
    cloud_resource_id: Optional[str] = None
    business_unit: Optional[str] = None
    department: Optional[str] = None
    owner_email: Optional[str] = None
    tags: Optional[Dict[str, Any]] = None
    notes: Optional[str] = None


class AssetUpdate(BaseModel):
    name: Optional[str] = None
    asset_type: Optional[str] = None
    environment: Optional[str] = None
    criticality_score: Optional[float] = Field(default=None, ge=0, le=10)
    business_impact_score: Optional[float] = Field(default=None, ge=0, le=10)
    data_classification: Optional[str] = None
    exposure_level: Optional[str] = None
    is_internet_facing: Optional[bool] = None
    is_in_compliance_scope: Optional[bool] = None
    business_unit: Optional[str] = None
    department: Optional[str] = None
    owner_email: Optional[str] = None
    tags: Optional[Dict[str, Any]] = None
    notes: Optional[str] = None
    status: Optional[str] = None


class AssetOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    asset_type: str
    status: str
    environment: str
    criticality_score: float
    criticality_label: str
    business_impact_score: float
    data_classification: str
    exposure_level: str
    is_internet_facing: bool
    is_in_compliance_scope: bool
    ip_addresses: Optional[Any] = None
    hostnames: Optional[Any] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    cloud_provider: Optional[str] = None
    cloud_region: Optional[str] = None
    business_unit: Optional[str] = None
    department: Optional[str] = None
    owner_email: Optional[str] = None
    security_health_score: float
    open_vuln_critical: int
    open_vuln_high: int
    open_vuln_medium: int
    open_vuln_low: int
    current_risk_score: Optional[float] = None
    current_risk_band: Optional[str] = None
    tags: Optional[Any] = None
    notes: Optional[str] = None
    last_scan_date: Optional[str] = None
    agent_last_checkin: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AssetListResponse(BaseModel):
    assets: List[AssetOut]
    total: int
    page: int
    per_page: int


class AssetSummary(BaseModel):
    total: int
    active: int
    critical_risk: int
    high_risk: int
    internet_facing: int
    never_scanned: int
    by_type: Dict[str, int]
    by_environment: Dict[str, int]
