from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RiskComponentOut(BaseModel):
    score: float
    weight: float
    contribution: float
    drivers: List[Dict[str, str]]


class AssetRiskScoreOut(BaseModel):
    asset_id: uuid.UUID
    risk_score: float
    risk_band: str
    confidence: float
    score_delta: Optional[float] = None
    formula_version: str
    trigger_event: Optional[str] = None
    components: Optional[Dict[str, RiskComponentOut]] = None
    top_drivers: Optional[Any] = None
    computed_at: datetime

    model_config = {"from_attributes": True}


class OrgRiskScoreOut(BaseModel):
    risk_score: float
    risk_band: str
    score_delta_7d: Optional[float] = None
    score_delta_30d: Optional[float] = None
    trend_direction: Optional[str] = None
    trend_velocity: Optional[float] = None
    projection_30d: Optional[float] = None
    assets_assessed: int
    assets_total: int
    critical_assets: int
    high_risk_assets: int

    model_config = {"from_attributes": True}


class RiskWeightConfigOut(BaseModel):
    id: uuid.UUID
    name: str
    vuln_weight: float
    exposure_weight: float
    business_weight: float
    posture_weight: float
    blast_radius_weight: float
    is_active: bool
    description: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class RiskWeightConfigCreate(BaseModel):
    name: str
    vuln_weight: float = Field(ge=0.20, le=0.70)
    exposure_weight: float = Field(ge=0.10, le=0.50)
    business_weight: float = Field(ge=0.05, le=0.40)
    posture_weight: float = Field(ge=0.05, le=0.30)
    blast_radius_weight: float = Field(ge=0.01, le=0.20)
    description: Optional[str] = None


class SimulationRequest(BaseModel):
    name: str
    remediation_plan: List[Dict[str, Any]]


class SimulationResult(BaseModel):
    simulation_id: uuid.UUID
    name: str
    current_score: float
    projected_score: float
    risk_reduction: float
    risk_reduction_pct: float
    asset_deltas: List[Dict[str, Any]]


class AssetRiskListResponse(BaseModel):
    assets: List[Dict[str, Any]]
    total: int
    summary: Dict[str, int]
